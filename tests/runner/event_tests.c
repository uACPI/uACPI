#include "helpers.h"
#include "tests.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <uacpi/event.h>
#include <uacpi/kernel_api.h>
#include <uacpi/namespace.h>
#include <uacpi/notify.h>
#include <uacpi/uacpi.h>

/*
 * The tests here might run with the work threads active, in which case the
 * usual error() is off limits: it resets the state of uACPI, and that is not
 * possible to do safely while another thread might still be inside of it.
 */
NORETURN static void fail(const char *format, ...)
{
    va_list args;

    fflush(stdout);

    fprintf(stderr, "unexpected error: ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputc('\n', stderr);

    exit(1);
}

#define CHECK(expr)                                                \
    do {                                                           \
        if (!(expr))                                               \
            fail("check '%s' at line %d failed", #expr, __LINE__); \
    } while (0)

#define CHECK_STATUS(expr, expected)                                \
    do {                                                            \
        uacpi_status check_st = (expr);                             \
                                                                    \
        if (check_st != (expected)) {                               \
            fail(                                                   \
                "'%s' at line %d returned '%s', expected '%s'",     \
                #expr, __LINE__, uacpi_status_to_string(check_st),  \
                uacpi_status_to_string(expected)                    \
            );                                                      \
        }                                                           \
    } while (0)

#define CHECK_OK(expr) CHECK_STATUS(expr, UACPI_STATUS_OK)

static uacpi_namespace_node *find_node(const char *path)
{
    uacpi_namespace_node *node = UACPI_NULL;

    CHECK_OK(uacpi_namespace_node_find(UACPI_NULL, path, &node));
    return node;
}

static void flush_work(void)
{
    CHECK_OK(uacpi_kernel_wait_for_work_completion());
}

typedef struct {
    size_t count;
    uacpi_namespace_node *node;
    uacpi_u64 value;
} notify_log_t;

static uacpi_status log_notify(
    uacpi_handle ctx, uacpi_namespace_node *node, uacpi_u64 value
)
{
    notify_log_t *log = ctx;

    log->count++;
    log->node = node;
    log->value = value;

    return UACPI_STATUS_OK;
}

/*
 * A notify handler is identified by its address, so we need a distinct function
 * for every handler that we want to have installed for a node at the same time.
 */
#define DEFINE_NOTIFY_HANDLER(name)                                    \
    static uacpi_status name(                                          \
        uacpi_handle ctx, uacpi_namespace_node *node, uacpi_u64 value  \
    )                                                                  \
    {                                                                  \
        return log_notify(ctx, node, value);                           \
    }

DEFINE_NOTIFY_HANDLER(notify_a)
DEFINE_NOTIFY_HANDLER(notify_b)

void test_notify_install_oom(void)
{
    uacpi_namespace_node *root = uacpi_namespace_root();
    uacpi_namespace_node *dev0 = find_node("\\DEV0");
    notify_log_t log = { 0 }, root_log = { 0 };

    /*
     * A leaked notify mutex makes pretty much everything below hang forever.
     * Do this with the work threads running so that we get terminated by the
     * watchdog if that happens.
     */
    work_threads_start();

    fail_next_alloc();
    CHECK_STATUS(
        uacpi_install_notify_handler(dev0, notify_a, &log),
        UACPI_STATUS_OUT_OF_MEMORY
    );

    fail_next_alloc();
    CHECK_STATUS(
        uacpi_install_notify_handler(root, notify_b, &root_log),
        UACPI_STATUS_OUT_OF_MEMORY
    );

    // Neither of the handlers is supposed to be there
    CHECK_STATUS(
        uacpi_uninstall_notify_handler(dev0, notify_a), UACPI_STATUS_NOT_FOUND
    );
    CHECK_STATUS(
        uacpi_uninstall_notify_handler(root, notify_b), UACPI_STATUS_NOT_FOUND
    );

    // Everything must still work as usual
    CHECK_OK(uacpi_install_notify_handler(dev0, notify_a, &log));
    CHECK_OK(uacpi_install_notify_handler(root, notify_b, &root_log));

    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF0"));
    flush_work();

    CHECK(log.count == 1);
    CHECK(log.node == dev0);
    CHECK(log.value == 0x80);
    CHECK(root_log.count == 1);

    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_a));
    CHECK_OK(uacpi_uninstall_notify_handler(root, notify_b));

    work_threads_stop();
}

static void gpe_set_status(uacpi_u16 idx)
{
    uacpi_io_addr base = FAKE_GPE0_BLK;

    if (idx >= FAKE_GPE1_BASE) {
        base = FAKE_GPE1_BLK;
        idx -= FAKE_GPE1_BASE;
    }

    fake_io_raise(base + idx / 8, (uint8_t)(1 << (idx % 8)));
}

// Trigger a GPE that is expected to be enabled, and thus handled
static void gpe_fire(uacpi_u16 idx)
{
    gpe_set_status(idx);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
}

DEFINE_NOTIFY_HANDLER(notify_c)
DEFINE_NOTIFY_HANDLER(notify_d)

// Evaluates a method that does a Notify() of its own
static uacpi_status notify_chain(
    uacpi_handle ctx, uacpi_namespace_node *node, uacpi_u64 value
)
{
    size_t *count = ctx;

    UACPI_UNUSED(node);
    UACPI_UNUSED(value);

    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF1"));
    *count += 1;

    return UACPI_STATUS_OK;
}

typedef struct {
    uacpi_handle entered;
    bool finished;
} slow_notify_t;

static uacpi_status notify_slow(
    uacpi_handle ctx, uacpi_namespace_node *node, uacpi_u64 value
)
{
    slow_notify_t *slow = ctx;

    UACPI_UNUSED(node);
    UACPI_UNUSED(value);

    uacpi_kernel_signal_event(slow->entered);

    /*
     * Don't go anywhere until we're waited for, which is what whoever is
     * uninstalling us is supposed to do, and what makes it safe for them to
     * get rid of everything that we're using as soon as they're done.
     */
    work_wait_for_waiter();
    slow->finished = true;

    return UACPI_STATUS_OK;
}

void test_notify_handlers_vs_work(void)
{
    uacpi_namespace_node *dev0 = find_node("\\DEV0");
    uacpi_namespace_node *dev1 = find_node("\\DEV1");
    notify_log_t a = { 0 }, b = { 0 }, c = { 0 }, d = { 0 };
    slow_notify_t slow = { 0 };
    size_t chain_count = 0;

    // This enables GPE 00, since it has an AML handler
    CHECK_OK(uacpi_finalize_gpe_initialization());

    // GPE 01 doesn't, make it notify DEV1 implicitly instead
    CHECK_OK(uacpi_setup_gpe_for_wake(UACPI_NULL, 1, dev1));
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 1));

    CHECK_OK(uacpi_install_notify_handler(dev0, notify_a, &a));
    CHECK_OK(uacpi_install_notify_handler(dev1, notify_c, &c));

    /*
     * Without the work threads everything happens right in the interrupt
     * handler: the GPE method is executed directly by the call that was
     * supposed to schedule it, and so is the notification that it produces.
     */
    gpe_fire(0);
    CHECK(a.count == 1);
    CHECK(a.node == dev0);
    CHECK(a.value == 0x80);

    work_threads_start();

    /*
     * Have a GPE handler that does a Notify() in flight while the handlers are
     * modified. The work is held until someone starts waiting for it, which is
     * something we must be able to do without preventing the Notify() from
     * making progress, or we hang forever.
     */
    work_hold();
    gpe_fire(0);

    CHECK_OK(uacpi_install_notify_handler(dev0, notify_b, &b));
    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_a));

    /*
     * The uninstall is guaranteed to have waited for the notification, which
     * was only produced after the handler was already gone.
     */
    CHECK(a.count == 1);
    CHECK(b.count == 1);
    CHECK(b.node == dev0);
    CHECK(b.value == 0x80);

    // Same thing, but with the notification coming straight from the GPE code
    work_hold();
    gpe_fire(1);

    CHECK_OK(uacpi_install_notify_handler(dev1, notify_d, &d));
    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_b));

    CHECK(b.count == 1);
    CHECK(c.count == 1);
    CHECK(c.node == dev1);
    CHECK(c.value == 2);
    CHECK(d.count == 1);

    /*
     * And once again, this time it's a notify handler that produces another
     * notification by evaluating a method.
     */
    CHECK_OK(uacpi_install_notify_handler(dev0, notify_chain, &chain_count));

    work_hold();
    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF0"));

    CHECK_OK(uacpi_uninstall_notify_handler(dev1, notify_d));

    CHECK(chain_count == 1);
    CHECK(c.count == 2);
    CHECK(c.value == 0x82);
    CHECK(d.count == 1);

    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_chain));

    /*
     * A handler that is running at the time of the uninstall must be waited
     * for, as it's free to go away as soon as the uninstall returns.
     */
    slow.entered = uacpi_kernel_create_event();
    CHECK(slow.entered != UACPI_NULL);
    CHECK_OK(uacpi_install_notify_handler(dev0, notify_slow, &slow));

    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF0"));
    CHECK(uacpi_kernel_wait_for_event(slow.entered, 0xFFFF));

    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_slow));
    CHECK(slow.finished);

    // Nobody is left to handle this one
    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF0"));
    flush_work();
    CHECK(a.count == 1);
    CHECK(b.count == 1);

    uacpi_kernel_free_event(slow.entered);
    CHECK_OK(uacpi_uninstall_notify_handler(dev1, notify_c));
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 1));

    work_threads_stop();
}
