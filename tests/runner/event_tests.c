#include "helpers.h"
#include "tests.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <uacpi/acpi.h>
#include <uacpi/event.h>
#include <uacpi/kernel_api.h>
#include <uacpi/namespace.h>
#include <uacpi/notify.h>
#include <uacpi/sleep.h>
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

    /*
     * A notification is delivered via a work item of its own, which is not
     * something that we're guaranteed to get either.
     */
    fail_next_work_item();
    CHECK_STATUS(
        uacpi_execute_simple(UACPI_NULL, "\\NTF0"), UACPI_STATUS_OUT_OF_MEMORY
    );
    flush_work();
    CHECK(log.count == 1);

    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF0"));
    flush_work();
    CHECK(log.count == 2);
    CHECK(root_log.count == 2);

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
    uacpi_namespace_node *node;
    notify_log_t *log;
    bool done;
} notify_reentrant_t;

DEFINE_NOTIFY_HANDLER(notify_e)

/*
 * Does what a handler is likely to do in response to a notification, all of
 * which involves calling back into uACPI: installs a handler for a different
 * node, and executes a method, which notifies that very node.
 */
static uacpi_status notify_reentrant(
    uacpi_handle ctx, uacpi_namespace_node *node, uacpi_u64 value
)
{
    notify_reentrant_t *reentrant = ctx;

    UACPI_UNUSED(node);
    UACPI_UNUSED(value);

    CHECK_OK(uacpi_install_notify_handler(
        reentrant->node, notify_e, reentrant->log
    ));
    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF1"));
    reentrant->done = true;

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

    uacpi_kernel_signal_semaphore(slow->entered);

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
    notify_log_t a = { 0 }, b = { 0 }, c = { 0 }, d = { 0 }, e = { 0 };
    notify_reentrant_t reentrant = { 0 };
    slow_notify_t slow = { 0 };
    size_t chain_count = 0;

    /*
     * Without the work threads a notification is delivered right by the call
     * that was supposed to schedule it, which is what a kernel might do if it
     * sees no reason to defer it. This must not get in the way of whatever the
     * handler is up to.
     */
    reentrant.node = dev1;
    reentrant.log = &e;
    CHECK_OK(uacpi_install_notify_handler(dev0, notify_reentrant, &reentrant));

    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF0"));
    CHECK(reentrant.done);
    CHECK(e.count == 1);
    CHECK(e.node == dev1);
    CHECK(e.value == 0x82);

    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_reentrant));
    CHECK_OK(uacpi_uninstall_notify_handler(dev1, notify_e));

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
    slow.entered = uacpi_kernel_create_semaphore(0);
    CHECK(slow.entered != UACPI_NULL);
    CHECK_OK(uacpi_install_notify_handler(dev0, notify_slow, &slow));

    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF0"));
    CHECK_OK(uacpi_kernel_wait_for_semaphore(slow.entered, 0xFFFF));

    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_slow));
    CHECK(slow.finished);

    // Nobody is left to handle this one
    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF0"));
    flush_work();
    CHECK(a.count == 1);
    CHECK(b.count == 1);

    uacpi_kernel_free_semaphore(slow.entered);
    CHECK_OK(uacpi_uninstall_notify_handler(dev1, notify_c));
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 1));

    work_threads_stop();
}

static uacpi_interrupt_ret gpe_handler_never_called(
    uacpi_handle ctx, uacpi_namespace_node *gpe_device, uacpi_u16 idx
)
{
    UACPI_UNUSED(ctx);
    UACPI_UNUSED(gpe_device);

    fail("GPE(%02X) handler called unexpectedly", idx);
    return UACPI_INTERRUPT_NOT_HANDLED;
}

static uacpi_interrupt_ret fixed_handler_never_called(uacpi_handle ctx)
{
    UACPI_UNUSED(ctx);

    fail("fixed event handler called unexpectedly");
    return UACPI_INTERRUPT_NOT_HANDLED;
}

/*
 * A notify handler that calls into the event API, same as something like an
 * embedded controller or a wake notification handler would.
 */
static uacpi_status notify_use_event_api(
    uacpi_handle ctx, uacpi_namespace_node *node, uacpi_u64 value
)
{
    size_t *count = ctx;
    uacpi_event_info info;

    UACPI_UNUSED(node);
    UACPI_UNUSED(value);

    CHECK_OK(uacpi_gpe_info(UACPI_NULL, 0, &info));
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 10));
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 10));
    CHECK_OK(uacpi_finish_handling_gpe(UACPI_NULL, 10));

    *count += 1;
    return UACPI_STATUS_OK;
}

/*
 * Queue a GPE handler that results in notify_use_event_api getting called,
 * and keep it from running until someone starts waiting for it.
 */
static void hold_event_api_work(void)
{
    work_hold();
    gpe_fire(0);
}

static uacpi_u64 eval_integer(const char *path)
{
    uacpi_u64 value = 0;

    CHECK_OK(uacpi_eval_simple_integer(UACPI_NULL, path, &value));
    return value;
}

void test_event_api_vs_work(void)
{
    uacpi_namespace_node *dev0 = find_node("\\DEV0");
    uacpi_namespace_node *dev1 = find_node("\\DEV1");
    uacpi_event_info info;
    size_t count = 0;

    // This enables GPEs 00, 02, 03, 08 and 09 since they have an AML handler
    CHECK_OK(uacpi_finalize_gpe_initialization());

    CHECK_OK(uacpi_install_gpe_handler(
        UACPI_NULL, 10, UACPI_GPE_TRIGGERING_LEVEL, gpe_handler_never_called,
        UACPI_NULL
    ));
    CHECK_OK(uacpi_install_notify_handler(dev0, notify_use_event_api, &count));

    work_threads_start();

    /*
     * All of the API below has to wait for the in-flight work to complete, as
     * the GPE that it reconfigures is enabled. This must be done in a way that
     * allows the work in question to make use of the event API, or both us and
     * the work hang forever.
     */
    hold_event_api_work();
    CHECK_OK(uacpi_mask_gpe(UACPI_NULL, 8));
    CHECK(count == 1);
    CHECK_OK(uacpi_unmask_gpe(UACPI_NULL, 8));

    hold_event_api_work();
    CHECK_OK(uacpi_install_gpe_handler(
        UACPI_NULL, 8, UACPI_GPE_TRIGGERING_LEVEL, gpe_handler_never_called,
        UACPI_NULL
    ));
    CHECK(count == 2);

    // A native handler is not enabled automatically, so do that by hand
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 8));

    hold_event_api_work();
    CHECK_OK(uacpi_uninstall_gpe_handler(
        UACPI_NULL, 8, gpe_handler_never_called
    ));
    CHECK(count == 3);
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 8));

    hold_event_api_work();
    CHECK_OK(uacpi_setup_gpe_for_wake(UACPI_NULL, 9, dev1));
    CHECK(count == 4);

    CHECK_OK(uacpi_install_fixed_event_handler(
        UACPI_FIXED_EVENT_POWER_BUTTON, fixed_handler_never_called, UACPI_NULL
    ));

    hold_event_api_work();
    CHECK_OK(uacpi_uninstall_fixed_event_handler(
        UACPI_FIXED_EVENT_POWER_BUTTON
    ));
    CHECK(count == 5);

    /*
     * Same as above, but this time it's a GPE handler that needs the event
     * lock, as it loads a table that provides a method for GPE 05.
     */
    CHECK_OK(uacpi_gpe_info(UACPI_NULL, 5, &info));
    CHECK(!(info & UACPI_EVENT_INFO_HAS_HANDLER));

    work_hold();
    gpe_fire(2);
    CHECK_OK(uacpi_mask_gpe(UACPI_NULL, 8));
    CHECK_OK(uacpi_unmask_gpe(UACPI_NULL, 8));

    CHECK_OK(uacpi_gpe_info(UACPI_NULL, 5, &info));
    CHECK(info & UACPI_EVENT_INFO_HAS_HANDLER);

    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 5));
    gpe_fire(5);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNT5") == 1);

    /*
     * An event is disabled while it's being handled, but there are ways to
     * enable it regardless. It must not be scheduled again if it fires at
     * that point, as that would be reusing a work item that is still pending,
     * and it must not be lost either.
     */
    work_hold();
    gpe_fire(5);
    CHECK_OK(uacpi_resume_gpe(UACPI_NULL, 5));
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNT5") == 2);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    // Same thing, but the event is edge triggered and thus fires once more
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 0x0B));

    work_hold();
    gpe_fire(0x0B);
    CHECK_OK(uacpi_resume_gpe(UACPI_NULL, 0x0B));
    gpe_fire(0x0B);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNTB") == 1);

    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNTB") == 2);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    /*
     * The handler of a GPE might get replaced while we wait for it to quiesce.
     * GPE 06 is configured for implicit notify at first, but ends up with an
     * AML handler by the time a native one is installed, so this is what must
     * be there after the native handler is gone.
     */
    CHECK_OK(uacpi_setup_gpe_for_wake(UACPI_NULL, 6, dev1));
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 6));

    work_hold();
    gpe_fire(3);
    CHECK_OK(uacpi_install_gpe_handler(
        UACPI_NULL, 6, UACPI_GPE_TRIGGERING_LEVEL, gpe_handler_never_called,
        UACPI_NULL
    ));
    CHECK_OK(uacpi_uninstall_gpe_handler(
        UACPI_NULL, 6, gpe_handler_never_called
    ));

    gpe_fire(6);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNT6") == 1);

    CHECK_OK(uacpi_uninstall_gpe_handler(
        UACPI_NULL, 10, gpe_handler_never_called
    ));
    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_use_event_api));

    work_threads_stop();
}

#define GPE_INFO_ENABLED (                                            \
    UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED |         \
    UACPI_EVENT_INFO_HW_ENABLED                                       \
)

#define CHECK_GPE_INFO(gpe_device, idx, expected)                         \
    do {                                                                  \
        uacpi_event_info check_info = 0;                                  \
                                                                          \
        CHECK_OK(uacpi_gpe_info(gpe_device, idx, &check_info));           \
        if ((unsigned)check_info != (unsigned)(expected)) {               \
            fail(                                                         \
                "GPE(%02X) info at line %d is 0x%02X, expected 0x%02X",   \
                (unsigned)(idx), __LINE__, (unsigned)check_info,          \
                (unsigned)(expected)                                      \
            );                                                            \
        }                                                                 \
    } while (0)

typedef struct {
    size_t count;
    uacpi_namespace_node *gpe_device;
    uacpi_u16 idx;
    uacpi_interrupt_ret ret;
} gpe_log_t;

static uacpi_interrupt_ret log_gpe(
    uacpi_handle ctx, uacpi_namespace_node *gpe_device, uacpi_u16 idx
)
{
    gpe_log_t *log = ctx;

    log->count++;
    log->gpe_device = gpe_device;
    log->idx = idx;

    return log->ret;
}

static uacpi_interrupt_ret log_gpe_other(
    uacpi_handle ctx, uacpi_namespace_node *gpe_device, uacpi_u16 idx
)
{
    return log_gpe(ctx, gpe_device, idx);
}

/*
 * This is executed twice: with the deferred work executed right by whoever
 * schedules it, and with it handed off to the work threads. All of the state
 * is expected to be left the way it was found.
 */
static void do_test_gpe_handlers(void)
{
    uacpi_namespace_node *gpe;
    uacpi_u64 cnt0, cnt1, cnt80, cntff;
    gpe_log_t log = { 0 };

    gpe = uacpi_namespace_get_predefined(UACPI_PREDEFINED_NAMESPACE_GPE);

    cnt0 = eval_integer("\\_GPE.CNT0");
    cnt1 = eval_integer("\\_GPE.CNT1");
    cnt80 = eval_integer("\\_GPE.CN80");
    cntff = eval_integer("\\_GPE.CNFF");

    // An event is disabled while it's handled, and is re-enabled afterwards
    gpe_fire(0);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNT0") == ++cnt0);
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);

    gpe_fire(1);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNT1") == ++cnt1);
    CHECK_GPE_INFO(UACPI_NULL, 1, GPE_INFO_ENABLED);

    // More than one event may be pending at once, even in the same register
    gpe_set_status(0);
    gpe_set_status(1);
    gpe_set_status(0x80);
    gpe_set_status(0xFF);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    flush_work();

    CHECK(eval_integer("\\_GPE.CNT0") == ++cnt0);
    CHECK(eval_integer("\\_GPE.CNT1") == ++cnt1);
    CHECK(eval_integer("\\_GPE.CN80") == ++cnt80);
    CHECK(eval_integer("\\_GPE.CNFF") == ++cntff);
    CHECK_GPE_INFO(UACPI_NULL, 0x80, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(UACPI_NULL, 0xFF, GPE_INFO_ENABLED);

    // An event that is not enabled is left alone
    gpe_set_status(2);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    CHECK_GPE_INFO(UACPI_NULL, 2, UACPI_EVENT_INFO_HW_STATUS);

    CHECK_OK(uacpi_clear_gpe(UACPI_NULL, 2));
    CHECK_GPE_INFO(UACPI_NULL, 2, 0);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    // An event stays enabled for as long as it has at least one user
    CHECK_STATUS(uacpi_enable_gpe(UACPI_NULL, 2), UACPI_STATUS_NO_HANDLER);
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 0));
    CHECK_OK(uacpi_enable_gpe(gpe, 0));
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 0));
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 0));
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);

    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 0));
    CHECK_GPE_INFO(UACPI_NULL, 0, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_STATUS(
        uacpi_disable_gpe(UACPI_NULL, 0), UACPI_STATUS_INVALID_ARGUMENT
    );

    gpe_set_status(0);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    // Whatever was pending before the first user came along is discarded
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 0));
    flush_work();
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);
    CHECK(eval_integer("\\_GPE.CNT0") == cnt0);

    // A suspended event is only disabled as far as the hardware is concerned
    CHECK_OK(uacpi_suspend_gpe(UACPI_NULL, 0));
    CHECK_GPE_INFO(
        UACPI_NULL, 0,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED
    );

    gpe_set_status(0);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    CHECK_OK(uacpi_resume_gpe(UACPI_NULL, 0));
    CHECK_GPE_INFO(
        UACPI_NULL, 0, GPE_INFO_ENABLED | UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNT0") == ++cnt0);
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);

    // A masked event can't be enabled no matter what
    CHECK_OK(uacpi_mask_gpe(UACPI_NULL, 0));
    CHECK_GPE_INFO(
        UACPI_NULL, 0,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED |
        UACPI_EVENT_INFO_MASKED
    );
    CHECK_STATUS(uacpi_mask_gpe(UACPI_NULL, 0), UACPI_STATUS_INVALID_ARGUMENT);

    CHECK_OK(uacpi_resume_gpe(UACPI_NULL, 0));
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 0));
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 0));
    CHECK_OK(uacpi_finish_handling_gpe(UACPI_NULL, 0));

    gpe_set_status(0);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    CHECK_GPE_INFO(
        UACPI_NULL, 0,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED |
        UACPI_EVENT_INFO_MASKED | UACPI_EVENT_INFO_HW_STATUS
    );

    // Not even by replacing its handler, which masks the event temporarily
    CHECK_OK(uacpi_install_gpe_handler(
        UACPI_NULL, 0, UACPI_GPE_TRIGGERING_LEVEL, log_gpe, &log
    ));
    CHECK_GPE_INFO(
        UACPI_NULL, 0,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_MASKED |
        UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK_OK(uacpi_uninstall_gpe_handler(UACPI_NULL, 0, log_gpe));
    CHECK_GPE_INFO(
        UACPI_NULL, 0,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED |
        UACPI_EVENT_INFO_MASKED | UACPI_EVENT_INFO_HW_STATUS
    );

    /*
     * Nor by re-enabling all of the runtime events, which is what happens
     * after waking up from sleep. The event is still expected to get enabled
     * as soon as it's unmasked though.
     */
    CHECK_OK(uacpi_disable_all_gpes());
    CHECK_GPE_INFO(
        UACPI_NULL, 1,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED
    );

    CHECK_OK(uacpi_enable_all_runtime_gpes());
    CHECK_GPE_INFO(UACPI_NULL, 1, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(
        UACPI_NULL, 0,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED |
        UACPI_EVENT_INFO_MASKED | UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK_OK(uacpi_unmask_gpe(UACPI_NULL, 0));
    CHECK_STATUS(
        uacpi_unmask_gpe(UACPI_NULL, 0), UACPI_STATUS_INVALID_ARGUMENT
    );
    CHECK_GPE_INFO(
        UACPI_NULL, 0, GPE_INFO_ENABLED | UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNT0") == ++cnt0);
    CHECK(log.count == 0);

    // And must be enabled again once it's been handled
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);

    /*
     * A native handler is invoked right away by the interrupt handler, and
     * decides whether the event is to be re-enabled once it returns.
     */
    CHECK_OK(uacpi_install_gpe_handler(
        UACPI_NULL, 10, UACPI_GPE_TRIGGERING_EDGE, log_gpe, &log
    ));
    CHECK_STATUS(
        uacpi_install_gpe_handler(
            UACPI_NULL, 10, UACPI_GPE_TRIGGERING_EDGE, log_gpe_other, &log
        ), UACPI_STATUS_ALREADY_EXISTS
    );
    CHECK_STATUS(
        uacpi_install_gpe_handler_raw(
            UACPI_NULL, 10, UACPI_GPE_TRIGGERING_EDGE, log_gpe_other, &log
        ), UACPI_STATUS_ALREADY_EXISTS
    );

    // It's up to whoever has installed the handler to enable the event
    CHECK_GPE_INFO(UACPI_NULL, 10, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 10));
    CHECK_GPE_INFO(UACPI_NULL, 10, GPE_INFO_ENABLED);

    log.ret = UACPI_INTERRUPT_HANDLED | UACPI_GPE_REENABLE;
    gpe_fire(10);
    CHECK(log.count == 1);
    CHECK(log.gpe_device == gpe);
    CHECK(log.idx == 10);
    CHECK_GPE_INFO(UACPI_NULL, 10, GPE_INFO_ENABLED);

    log.ret = UACPI_INTERRUPT_HANDLED;
    gpe_fire(10);
    CHECK(log.count == 2);
    CHECK_GPE_INFO(
        UACPI_NULL, 10,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED
    );

    gpe_set_status(10);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    CHECK(log.count == 2);

    CHECK_OK(uacpi_finish_handling_gpe(UACPI_NULL, 10));
    CHECK_GPE_INFO(
        UACPI_NULL, 10, GPE_INFO_ENABLED | UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(log.count == 3);
    CHECK_OK(uacpi_finish_handling_gpe(UACPI_NULL, 10));
    CHECK_GPE_INFO(UACPI_NULL, 10, GPE_INFO_ENABLED);

    CHECK_STATUS(
        uacpi_uninstall_gpe_handler(UACPI_NULL, 10, log_gpe_other),
        UACPI_STATUS_INVALID_ARGUMENT
    );
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 10));
    CHECK_OK(uacpi_uninstall_gpe_handler(UACPI_NULL, 10, log_gpe));
    CHECK_STATUS(
        uacpi_uninstall_gpe_handler(UACPI_NULL, 10, log_gpe),
        UACPI_STATUS_NOT_FOUND
    );
    CHECK_GPE_INFO(UACPI_NULL, 10, 0);

    /*
     * A native handler takes precedence over an AML one, which is restored
     * to the state it was in once the native handler is gone.
     */
    log.count = 0;
    log.ret = UACPI_INTERRUPT_HANDLED | UACPI_GPE_REENABLE;

    CHECK_OK(uacpi_install_gpe_handler(
        UACPI_NULL, 1, UACPI_GPE_TRIGGERING_EDGE, log_gpe, &log
    ));
    CHECK_GPE_INFO(UACPI_NULL, 1, UACPI_EVENT_INFO_HAS_HANDLER);

    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 1));
    gpe_fire(1);
    flush_work();
    CHECK(log.count == 1);
    CHECK(log.idx == 1);
    CHECK(eval_integer("\\_GPE.CNT1") == cnt1);
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 1));

    /*
     * An edge triggered event that became pending in the meantime is not
     * going to raise an interrupt, and so has to be dispatched by hand.
     */
    gpe_set_status(1);
    CHECK_OK(uacpi_uninstall_gpe_handler(UACPI_NULL, 1, log_gpe));
    flush_work();
    CHECK(log.count == 1);
    CHECK(eval_integer("\\_GPE.CNT1") == ++cnt1);
    CHECK_GPE_INFO(UACPI_NULL, 1, GPE_INFO_ENABLED);

    /*
     * This only applies to an event that is actually able to fire, which is
     * not the case for one that is masked: it must be left alone until it's
     * unmasked.
     */
    CHECK_OK(uacpi_mask_gpe(UACPI_NULL, 1));
    CHECK_OK(uacpi_install_gpe_handler(
        UACPI_NULL, 1, UACPI_GPE_TRIGGERING_EDGE, log_gpe, &log
    ));

    gpe_set_status(1);
    CHECK_OK(uacpi_uninstall_gpe_handler(UACPI_NULL, 1, log_gpe));
    flush_work();
    CHECK(log.count == 1);
    CHECK(eval_integer("\\_GPE.CNT1") == cnt1);
    CHECK_GPE_INFO(
        UACPI_NULL, 1,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED |
        UACPI_EVENT_INFO_MASKED | UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK_OK(uacpi_unmask_gpe(UACPI_NULL, 1));
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    flush_work();
    CHECK(eval_integer("\\_GPE.CNT1") == ++cnt1);
    CHECK_GPE_INFO(UACPI_NULL, 1, GPE_INFO_ENABLED);

    // A raw handler is on its own, we don't touch the event in any way
    log.count = 0;
    log.ret = UACPI_INTERRUPT_HANDLED;

    CHECK_OK(uacpi_install_gpe_handler_raw(
        UACPI_NULL, 11, UACPI_GPE_TRIGGERING_LEVEL, log_gpe, &log
    ));
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 11));

    gpe_fire(11);
    CHECK(log.count == 1);
    CHECK(log.idx == 11);
    CHECK_GPE_INFO(
        UACPI_NULL, 11, GPE_INFO_ENABLED | UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(log.count == 2);

    CHECK_OK(uacpi_clear_gpe(UACPI_NULL, 11));
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    CHECK(log.count == 2);

    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 11));
    CHECK_OK(uacpi_uninstall_gpe_handler(UACPI_NULL, 11, log_gpe));
    CHECK_GPE_INFO(UACPI_NULL, 11, 0);

    /*
     * That still doesn't make it okay to invoke the handler for an event that
     * is not able to fire, which is the case for the one that is masked, even
     * if it happens to be pending at the time that it's polled.
     */
    CHECK_OK(uacpi_install_gpe_handler_raw(
        UACPI_NULL, 11, UACPI_GPE_TRIGGERING_EDGE, log_gpe, &log
    ));
    CHECK_OK(uacpi_mask_gpe(UACPI_NULL, 11));
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 11));

    gpe_set_status(11);
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 11));
    CHECK(log.count == 2);

    CHECK_OK(uacpi_unmask_gpe(UACPI_NULL, 11));
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(log.count == 3);

    CHECK_OK(uacpi_clear_gpe(UACPI_NULL, 11));
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 11));
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 11));
    CHECK_OK(uacpi_uninstall_gpe_handler(UACPI_NULL, 11, log_gpe));
    CHECK_GPE_INFO(UACPI_NULL, 11, 0);
}

void test_gpe_handlers(void)
{
    uacpi_namespace_node *dev0 = find_node("\\DEV0");
    uacpi_namespace_node *gpe;
    uacpi_event_info info;

    gpe = uacpi_namespace_get_predefined(UACPI_PREDEFINED_NAMESPACE_GPE);

    // The events that have a method are matched, but are not enabled just yet
    CHECK_GPE_INFO(UACPI_NULL, 0, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_GPE_INFO(gpe, 1, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_GPE_INFO(UACPI_NULL, 2, 0);
    CHECK_GPE_INFO(UACPI_NULL, 0x7F, 0);
    CHECK_GPE_INFO(UACPI_NULL, 0x80, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_GPE_INFO(UACPI_NULL, 0xFF, UACPI_EVENT_INFO_HAS_HANDLER);

    // Right past the end of the last block
    CHECK_STATUS(
        uacpi_gpe_info(UACPI_NULL, 0x100, &info), UACPI_STATUS_NOT_FOUND
    );
    CHECK_STATUS(uacpi_enable_gpe(UACPI_NULL, 0x100), UACPI_STATUS_NOT_FOUND);
    CHECK_STATUS(
        uacpi_install_gpe_handler(
            UACPI_NULL, 0x100, UACPI_GPE_TRIGGERING_EDGE, log_gpe, UACPI_NULL
        ), UACPI_STATUS_NOT_FOUND
    );

    // Not a device that has any events
    CHECK_STATUS(uacpi_gpe_info(dev0, 0, &info), UACPI_STATUS_NOT_FOUND);

    /*
     * This is what enables the events. An edge triggered one that is already
     * pending wouldn't raise an interrupt, so it's dispatched right away.
     */
    gpe_set_status(1);
    CHECK_OK(uacpi_finalize_gpe_initialization());
    CHECK(eval_integer("\\_GPE.CNT1") == 1);

    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(UACPI_NULL, 1, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(UACPI_NULL, 2, 0);
    CHECK_GPE_INFO(UACPI_NULL, 0x80, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(UACPI_NULL, 0xFF, GPE_INFO_ENABLED);

    // Doing it more than once has no effect
    CHECK_OK(uacpi_finalize_gpe_initialization());
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 0xFF));
    CHECK_GPE_INFO(UACPI_NULL, 0xFF, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 0xFF));

    do_test_gpe_handlers();

    work_threads_start();
    do_test_gpe_handlers();
    work_threads_stop();
}

void test_wake_gpes(void)
{
    uacpi_namespace_node *dev0 = find_node("\\DEV0");
    uacpi_namespace_node *dev1 = find_node("\\DEV1");
    uacpi_namespace_node *dev2 = find_node("\\DEV2");
    notify_log_t log0 = { 0 }, log1 = { 0 }, log2 = { 0 };

    /*
     * An event that is marked as wake is not enabled along with the rest of
     * the events that have a handler, it's on whoever marked it to do that.
     */
    CHECK_STATUS(
        uacpi_setup_gpe_for_wake(UACPI_NULL, 3, find_node("\\MAIN")),
        UACPI_STATUS_INVALID_ARGUMENT
    );
    CHECK_OK(uacpi_setup_gpe_for_wake(UACPI_NULL, 3, UACPI_NULL));

    CHECK_OK(uacpi_finalize_gpe_initialization());
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(UACPI_NULL, 3, UACPI_EVENT_INFO_HAS_HANDLER);

    // The handler of GPE 03 is expected to notify the device as needed
    CHECK_OK(uacpi_setup_gpe_for_wake(UACPI_NULL, 3, dev0));
    CHECK_GPE_INFO(UACPI_NULL, 3, UACPI_EVENT_INFO_HAS_HANDLER);

    // GPEs 10 and 11 have no handler, so that is something we do ourselves
    CHECK_GPE_INFO(UACPI_NULL, 0x10, 0);

    // This is done via deferred work, which the event needs a work item for
    fail_next_work_item();
    CHECK_STATUS(
        uacpi_setup_gpe_for_wake(UACPI_NULL, 0x10, dev1),
        UACPI_STATUS_OUT_OF_MEMORY
    );
    CHECK_GPE_INFO(UACPI_NULL, 0x10, 0);

    CHECK_OK(uacpi_setup_gpe_for_wake(UACPI_NULL, 0x10, dev1));
    CHECK_GPE_INFO(UACPI_NULL, 0x10, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_STATUS(
        uacpi_setup_gpe_for_wake(UACPI_NULL, 0x10, dev1),
        UACPI_STATUS_ALREADY_EXISTS
    );

    // An event may be shared by multiple devices
    CHECK_OK(uacpi_setup_gpe_for_wake(UACPI_NULL, 0x10, dev2));
    CHECK_OK(uacpi_setup_gpe_for_wake(UACPI_NULL, 0x11, dev2));

    CHECK_OK(uacpi_install_notify_handler(dev0, notify_a, &log0));
    CHECK_OK(uacpi_install_notify_handler(dev1, notify_a, &log1));
    CHECK_OK(uacpi_install_notify_handler(dev2, notify_a, &log2));

    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 3));
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 0x10));
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 0x11));

    gpe_fire(3);
    CHECK(eval_integer("\\_GPE.CNT3") == 1);
    CHECK(log0.count == 1);
    CHECK(log0.node == dev0);
    CHECK(log0.value == 2);
    CHECK_GPE_INFO(UACPI_NULL, 3, GPE_INFO_ENABLED);

    gpe_fire(0x10);
    CHECK(log1.count == 1);
    CHECK(log1.node == dev1);
    CHECK(log1.value == 2);
    CHECK(log2.count == 1);
    CHECK(log2.node == dev2);
    CHECK(log2.value == 2);
    CHECK_GPE_INFO(UACPI_NULL, 0x10, GPE_INFO_ENABLED);

    // Same thing, but with the notifications delivered by the work threads
    work_threads_start();

    gpe_fire(0x11);
    flush_work();
    CHECK(log1.count == 1);
    CHECK(log2.count == 2);
    CHECK_GPE_INFO(UACPI_NULL, 0x11, GPE_INFO_ENABLED);

    /*
     * An event that was disabled right after being dispatched still has work
     * in flight. This work must be waited for before the handler of the event
     * is replaced, or the notification is lost.
     */
    work_hold();
    gpe_fire(0x11);
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 0x11));

    CHECK_OK(uacpi_install_gpe_handler(
        UACPI_NULL, 0x11, UACPI_GPE_TRIGGERING_LEVEL, gpe_handler_never_called,
        UACPI_NULL
    ));
    CHECK(log2.count == 3);

    CHECK_OK(uacpi_uninstall_gpe_handler(
        UACPI_NULL, 0x11, gpe_handler_never_called
    ));
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 0x11));
    CHECK_GPE_INFO(UACPI_NULL, 0x11, GPE_INFO_ENABLED);

    work_threads_stop();

    // Only an event that is marked as wake can be enabled for it
    CHECK_STATUS(
        uacpi_enable_gpe_for_wake(UACPI_NULL, 0),
        UACPI_STATUS_INVALID_ARGUMENT
    );
    CHECK_OK(uacpi_enable_gpe_for_wake(UACPI_NULL, 3));
    CHECK_OK(uacpi_enable_gpe_for_wake(UACPI_NULL, 0x10));
    CHECK_OK(uacpi_enable_gpe_for_wake(UACPI_NULL, 0x11));
    CHECK_GPE_INFO(
        UACPI_NULL, 0x10,
        GPE_INFO_ENABLED | UACPI_EVENT_INFO_ENABLED_FOR_WAKE
    );

    // This must not affect GPE 11, which lives in the same register
    CHECK_OK(uacpi_disable_gpe_for_wake(UACPI_NULL, 0x10));
    CHECK_GPE_INFO(UACPI_NULL, 0x10, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(
        UACPI_NULL, 0x11,
        GPE_INFO_ENABLED | UACPI_EVENT_INFO_ENABLED_FOR_WAKE
    );
    CHECK_GPE_INFO(
        UACPI_NULL, 3, GPE_INFO_ENABLED | UACPI_EVENT_INFO_ENABLED_FOR_WAKE
    );

    // Only the events that are enabled for wake stay on when going to sleep
    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 3));
    CHECK_OK(uacpi_enable_all_wake_gpes());
    CHECK_GPE_INFO(
        UACPI_NULL, 0,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED
    );
    CHECK_GPE_INFO(
        UACPI_NULL, 3,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED_FOR_WAKE |
        UACPI_EVENT_INFO_HW_ENABLED
    );
    CHECK_GPE_INFO(
        UACPI_NULL, 0x10,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED
    );
    CHECK_GPE_INFO(
        UACPI_NULL, 0x11,
        GPE_INFO_ENABLED | UACPI_EVENT_INFO_ENABLED_FOR_WAKE
    );

    // And the other way around once we're back
    CHECK_OK(uacpi_enable_all_runtime_gpes());
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(
        UACPI_NULL, 3,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED_FOR_WAKE
    );
    CHECK_GPE_INFO(UACPI_NULL, 0x10, GPE_INFO_ENABLED);

    CHECK_OK(uacpi_disable_all_gpes());
    CHECK_GPE_INFO(
        UACPI_NULL, 0,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED
    );
    CHECK_GPE_INFO(
        UACPI_NULL, 0x11,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED |
        UACPI_EVENT_INFO_ENABLED_FOR_WAKE
    );

    gpe_set_status(0);
    gpe_set_status(0x10);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    CHECK_OK(uacpi_clear_gpe(UACPI_NULL, 0));
    CHECK_OK(uacpi_clear_gpe(UACPI_NULL, 0x10));
    CHECK_GPE_INFO(
        UACPI_NULL, 0,
        UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED
    );

    CHECK_OK(uacpi_enable_all_runtime_gpes());
    gpe_fire(0);
    CHECK(eval_integer("\\_GPE.CNT0") == 1);
    CHECK(log1.count == 1);

    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_a));
    CHECK_OK(uacpi_uninstall_notify_handler(dev1, notify_a));
    CHECK_OK(uacpi_uninstall_notify_handler(dev2, notify_a));

    /*
     * Replace an implicit notify handler with a native one, and leave it be.
     * Both are expected to be released when uACPI is deinitialized.
     */
    CHECK_OK(uacpi_install_gpe_handler(
        UACPI_NULL, 0x10, UACPI_GPE_TRIGGERING_LEVEL, gpe_handler_never_called,
        UACPI_NULL
    ));
}

#define GPEB_ADDRESS 0x1000
#define GPEB_NUM_REGISTERS 2

#define GPEC_ADDRESS 0x1100
#define GPEC_NUM_REGISTERS 1

#define GPE_BLOCK_IRQ 11
#define GPE_BLOCK_OTHER_IRQ 12

static void gpe_block_fire(uacpi_io_addr base, uacpi_u32 irq, uacpi_u16 idx)
{
    fake_io_raise(base + idx / 8, (uint8_t)(1 << (idx % 8)));
    CHECK(fake_irq_raise(irq) == UACPI_INTERRUPT_HANDLED);
}

typedef struct {
    uacpi_namespace_node *gpe_device;
    size_t count;
} gpe_block_user_t;

/*
 * Called while the block is in the middle of being uninstalled. Enable an
 * event from a register that might've not been looked at just yet.
 */
static uacpi_status notify_use_gpe_block(
    uacpi_handle ctx, uacpi_namespace_node *node, uacpi_u64 value
)
{
    gpe_block_user_t *user = ctx;
    uacpi_event_info info;

    UACPI_UNUSED(node);
    UACPI_UNUSED(value);

    CHECK_OK(uacpi_gpe_info(user->gpe_device, 0, &info));
    CHECK_OK(uacpi_enable_gpe(user->gpe_device, 9));

    user->count++;
    return UACPI_STATUS_OK;
}

typedef struct {
    // The IO access to take the interrupt at
    fake_io_op op;
    uacpi_io_addr addr;

    // The interrupt to take, and the register to park its handler at
    uacpi_u32 irq;
    uacpi_io_addr park_addr;

    bool was_taken;
    bool was_parked;
} irq_injection_t;

/*
 * Takes an interrupt on a different thread right before a specific IO access
 * is made, and leaves the handler parked in case it gets to look at the
 * register that we're interested in.
 */
static void inject_irq(void *ctx, fake_io_op op, uacpi_io_addr addr)
{
    irq_injection_t *injection = ctx;

    if (injection->was_taken || op != injection->op ||
        addr != injection->addr)
        return;

    injection->was_taken = true;
    injection->was_parked = fake_irq_raise_parked(
        injection->irq, injection->park_addr
    );
}

void test_gpe_blocks(void)
{
    uacpi_namespace_node *dev0 = find_node("\\DEV0");
    uacpi_namespace_node *gpeb = find_node("\\GPEB");
    uacpi_namespace_node *gpec = find_node("\\GPEC");
    notify_log_t log = { 0 };
    gpe_block_user_t user = { 0 };
    irq_injection_t injection = { 0 };
    uacpi_event_info info;

    fake_io_set_write_one_to_clear(GPEB_ADDRESS, GPEB_NUM_REGISTERS);
    fake_io_set_write_one_to_clear(GPEC_ADDRESS, GPEC_NUM_REGISTERS);

    CHECK_STATUS(uacpi_gpe_info(gpeb, 0, &info), UACPI_STATUS_NOT_FOUND);
    CHECK_STATUS(uacpi_uninstall_gpe_block(gpeb), UACPI_STATUS_NOT_FOUND);
    CHECK_STATUS(
        uacpi_install_gpe_block(
            find_node("\\MAIN"), GPEB_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
            GPEB_NUM_REGISTERS, GPE_BLOCK_IRQ
        ), UACPI_STATUS_INVALID_ARGUMENT
    );

    CHECK_OK(uacpi_install_gpe_block(
        gpeb, GPEB_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
        GPEB_NUM_REGISTERS, GPE_BLOCK_IRQ
    ));
    CHECK_STATUS(
        uacpi_install_gpe_block(
            gpeb, GPEB_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
            GPEB_NUM_REGISTERS, GPE_BLOCK_IRQ
        ), UACPI_STATUS_ALREADY_EXISTS
    );

    // The methods are looked up in the scope of the device
    CHECK_GPE_INFO(gpeb, 0, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_GPE_INFO(gpeb, 1, 0);
    CHECK_GPE_INFO(gpeb, 9, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_GPE_INFO(gpeb, 15, 0);
    CHECK_STATUS(uacpi_gpe_info(gpeb, 16, &info), UACPI_STATUS_NOT_FOUND);

    // And have nothing to do with the events described by the FADT
    CHECK_GPE_INFO(UACPI_NULL, 0, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_GPE_INFO(UACPI_NULL, 9, 0);

    /*
     * The events of every block that exists at this point get enabled. Those
     * that are already pending are dispatched as well, no matter which of the
     * interrupts the block belongs to.
     */
    gpe_set_status(1);
    fake_io_raise(GPEB_ADDRESS + 1, 1 << 1);

    CHECK_OK(uacpi_finalize_gpe_initialization());
    CHECK(eval_integer("\\_GPE.CNT1") == 1);
    CHECK(eval_integer("\\GPEB.CNT9") == 1);

    CHECK_GPE_INFO(gpeb, 0, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(gpeb, 9, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(UACPI_NULL, 1, GPE_INFO_ENABLED);

    /*
     * A block that is installed later on has to be finalized as well. This is
     * not done right away so that we get a chance to mark its wake events.
     */
    CHECK_OK(uacpi_install_gpe_block(
        gpec, GPEC_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
        GPEC_NUM_REGISTERS, GPE_BLOCK_IRQ
    ));
    CHECK_GPE_INFO(gpec, 1, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_GPE_INFO(gpec, 2, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_GPE_INFO(gpec, 3, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_STATUS(uacpi_gpe_info(gpec, 8, &info), UACPI_STATUS_NOT_FOUND);

    CHECK_OK(uacpi_setup_gpe_for_wake(gpec, 2, UACPI_NULL));

    // An edge triggered event that is already pending is dispatched as well
    fake_io_raise(GPEC_ADDRESS, 1 << 3);
    CHECK_OK(uacpi_finalize_gpe_initialization());
    CHECK(eval_integer("\\GPEC.CNT3") == 1);

    CHECK_GPE_INFO(gpec, 1, GPE_INFO_ENABLED);
    CHECK_GPE_INFO(gpec, 2, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_GPE_INFO(gpec, 3, GPE_INFO_ENABLED);

    // The blocks that were finalized earlier must not get enabled twice
    CHECK_OK(uacpi_disable_gpe(gpeb, 9));
    CHECK_GPE_INFO(gpeb, 9, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_OK(uacpi_enable_gpe(gpeb, 9));

    CHECK_OK(uacpi_disable_gpe(UACPI_NULL, 0));
    CHECK_GPE_INFO(UACPI_NULL, 0, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_OK(uacpi_enable_gpe(UACPI_NULL, 0));

    CHECK_OK(uacpi_install_notify_handler(dev0, notify_a, &log));

    gpe_block_fire(GPEB_ADDRESS, GPE_BLOCK_IRQ, 0);
    CHECK(eval_integer("\\GPEB.CNT0") == 1);
    CHECK(log.count == 1);
    CHECK_GPE_INFO(gpeb, 0, GPE_INFO_ENABLED);

    gpe_block_fire(GPEB_ADDRESS, GPE_BLOCK_IRQ, 9);
    CHECK(eval_integer("\\GPEB.CNT9") == 2);

    gpe_block_fire(GPEC_ADDRESS, GPE_BLOCK_IRQ, 1);
    CHECK(eval_integer("\\GPEC.CNT1") == 1);

    gpe_fire(0);
    CHECK(eval_integer("\\_GPE.CNT0") == 1);
    CHECK(eval_integer("\\GPEB.CNT0") == 1);

    // A block is only serviced by the interrupt that it was installed for
    fake_io_raise(GPEB_ADDRESS, 1);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    CHECK(fake_irq_raise(GPE_BLOCK_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(eval_integer("\\GPEB.CNT0") == 2);

    // The interrupt stays around for as long as there's a block that uses it
    CHECK_OK(uacpi_uninstall_gpe_block(gpeb));
    CHECK_STATUS(uacpi_gpe_info(gpeb, 0, &info), UACPI_STATUS_NOT_FOUND);

    fake_io_raise(GPEB_ADDRESS, 1);
    CHECK(fake_irq_raise(GPE_BLOCK_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    gpe_block_fire(GPEC_ADDRESS, GPE_BLOCK_IRQ, 1);
    CHECK(eval_integer("\\GPEC.CNT1") == 2);

    CHECK_OK(uacpi_uninstall_gpe_block(gpec));
    CHECK_STATUS(uacpi_uninstall_gpe_block(gpec), UACPI_STATUS_NOT_FOUND);

    fake_io_raise(GPEC_ADDRESS, 2);
    CHECK(fake_irq_raise(GPE_BLOCK_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    // None of the above is supposed to have any effect on the other blocks
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);
    gpe_fire(0);
    CHECK(eval_integer("\\_GPE.CNT0") == 2);

    // A block that shares the interrupt with the FADT ones
    CHECK_OK(uacpi_install_gpe_block(
        gpec, GPEC_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
        GPEC_NUM_REGISTERS, FAKE_SCI_IRQ
    ));
    CHECK_GPE_INFO(gpec, 1, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_OK(uacpi_enable_gpe(gpec, 1));

    gpe_block_fire(GPEC_ADDRESS, FAKE_SCI_IRQ, 1);
    CHECK(eval_integer("\\GPEC.CNT1") == 3);

    CHECK_OK(uacpi_uninstall_gpe_block(gpec));
    gpe_fire(0);
    CHECK(eval_integer("\\_GPE.CNT0") == 3);

    /*
     * Uninstall a block while one of its events is being handled. The handler
     * notifies DEV0, which then goes on to enable an event from the second
     * register of that very block.
     */
    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_a));

    CHECK_OK(uacpi_install_gpe_block(
        gpeb, GPEB_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
        GPEB_NUM_REGISTERS, GPE_BLOCK_OTHER_IRQ
    ));
    CHECK_GPE_INFO(gpeb, 0, UACPI_EVENT_INFO_HAS_HANDLER);
    CHECK_OK(uacpi_enable_gpe(gpeb, 0));

    user.gpe_device = gpeb;
    CHECK_OK(uacpi_install_notify_handler(dev0, notify_use_gpe_block, &user));

    work_threads_start();

    work_hold();
    gpe_block_fire(GPEB_ADDRESS, GPE_BLOCK_OTHER_IRQ, 0);

    CHECK_OK(uacpi_uninstall_gpe_block(gpeb));
    CHECK(user.count == 1);
    CHECK(eval_integer("\\GPEB.CNT0") == 3);

    /*
     * Same goes for an event that was disabled right after being dispatched:
     * the work that is in flight still refers to it, and so has to be waited
     * for before the block is gone.
     */
    CHECK_OK(uacpi_install_gpe_block(
        gpeb, GPEB_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
        GPEB_NUM_REGISTERS, GPE_BLOCK_OTHER_IRQ
    ));
    CHECK_OK(uacpi_enable_gpe(gpeb, 0));

    work_hold();
    gpe_block_fire(GPEB_ADDRESS, GPE_BLOCK_OTHER_IRQ, 0);
    CHECK_OK(uacpi_disable_gpe(gpeb, 0));

    CHECK_OK(uacpi_uninstall_gpe_block(gpeb));
    CHECK(user.count == 2);
    CHECK(eval_integer("\\GPEB.CNT0") == 4);

    /*
     * Take an interrupt on a different CPU right as the last of the events is
     * disabled. Its handler is in the middle of looking at the block, which
     * therefore must not go away until the handler has returned.
     */
    CHECK_OK(uacpi_install_gpe_block(
        gpeb, GPEB_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
        GPEB_NUM_REGISTERS, GPE_BLOCK_OTHER_IRQ
    ));
    CHECK_OK(uacpi_enable_gpe(gpeb, 0));

    injection.op = FAKE_IO_OP_WRITE;
    injection.addr = GPEB_ADDRESS + GPEB_NUM_REGISTERS * 2 - 1;
    injection.irq = GPE_BLOCK_OTHER_IRQ;
    injection.park_addr = GPEB_ADDRESS;
    fake_io_set_hook(inject_irq, &injection);

    CHECK_OK(uacpi_uninstall_gpe_block(gpeb));
    CHECK(injection.was_taken);
    CHECK(injection.was_parked);
    CHECK(!fake_irq_is_parked());

    /*
     * Same thing, but this time take it right as the registers of the block
     * are unmapped. The block is not supposed to be reachable by an interrupt
     * handler at that point.
     *
     * The block shares the SCI this time around: that is the one interrupt
     * whose handler is guaranteed to still be there, with nothing but the
     * block being unlinked to keep it away.
     */
    fake_io_set_hook(UACPI_NULL, UACPI_NULL);

    CHECK_OK(uacpi_install_gpe_block(
        gpeb, GPEB_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
        GPEB_NUM_REGISTERS, FAKE_SCI_IRQ
    ));
    CHECK_OK(uacpi_enable_gpe(gpeb, 0));

    injection.op = FAKE_IO_OP_UNMAP;
    injection.addr = GPEB_ADDRESS;
    injection.irq = FAKE_SCI_IRQ;
    injection.was_taken = false;
    injection.was_parked = false;
    fake_io_set_hook(inject_irq, &injection);

    CHECK_OK(uacpi_uninstall_gpe_block(gpeb));
    CHECK(injection.was_taken);
    CHECK(!injection.was_parked);

    fake_io_set_hook(UACPI_NULL, UACPI_NULL);

    work_threads_stop();

    CHECK_STATUS(uacpi_gpe_info(gpeb, 9, &info), UACPI_STATUS_NOT_FOUND);

    fake_io_raise(GPEB_ADDRESS + 1, 2);
    CHECK(
        fake_irq_raise(GPE_BLOCK_OTHER_IRQ) == UACPI_INTERRUPT_NOT_HANDLED
    );

    CHECK_OK(uacpi_uninstall_notify_handler(dev0, notify_use_gpe_block));
    CHECK_GPE_INFO(UACPI_NULL, 0, GPE_INFO_ENABLED);
}

#define FIXED_INFO_ENABLED (                                          \
    UACPI_EVENT_INFO_HAS_HANDLER | UACPI_EVENT_INFO_ENABLED |         \
    UACPI_EVENT_INFO_HW_ENABLED                                       \
)

#define CHECK_FIXED_INFO(event, expected)                                 \
    do {                                                                  \
        uacpi_event_info check_info = 0;                                  \
                                                                          \
        CHECK_OK(uacpi_fixed_event_info(event, &check_info));             \
        if ((unsigned)check_info != (unsigned)(expected)) {               \
            fail(                                                         \
                "fixed event %d info at line %d is 0x%02X, expected "     \
                "0x%02X", (int)(event), __LINE__, (unsigned)check_info,   \
                (unsigned)(expected)                                      \
            );                                                            \
        }                                                                 \
    } while (0)

typedef struct {
    size_t count;
} fixed_log_t;

static uacpi_interrupt_ret log_fixed_event(uacpi_handle ctx)
{
    fixed_log_t *log = ctx;

    log->count++;
    return UACPI_INTERRUPT_HANDLED;
}

static void fixed_event_set_status(uacpi_u16 mask)
{
    fake_io_raise(FAKE_PM1A_EVT_BLK, (uint8_t)(mask & 0xFF));
    fake_io_raise(FAKE_PM1A_EVT_BLK + 1, (uint8_t)(mask >> 8));
}

void test_fixed_events(void)
{
    fixed_log_t power = { 0 }, rtc = { 0 };

    CHECK_STATUS(
        uacpi_install_fixed_event_handler(
            UACPI_FIXED_EVENT_MAX + 1, log_fixed_event, UACPI_NULL
        ), UACPI_STATUS_INVALID_ARGUMENT
    );
    CHECK_STATUS(
        uacpi_enable_fixed_event(UACPI_FIXED_EVENT_POWER_BUTTON),
        UACPI_STATUS_NO_HANDLER
    );
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_POWER_BUTTON, 0);

    // An event is enabled as soon as it has a handler
    CHECK_OK(uacpi_install_fixed_event_handler(
        UACPI_FIXED_EVENT_POWER_BUTTON, log_fixed_event, &power
    ));
    CHECK_STATUS(
        uacpi_install_fixed_event_handler(
            UACPI_FIXED_EVENT_POWER_BUTTON, log_fixed_event, &power
        ), UACPI_STATUS_ALREADY_EXISTS
    );
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_POWER_BUTTON, FIXED_INFO_ENABLED);

    fixed_event_set_status(ACPI_PM1_STS_PWRBTN_STS_MASK);
    CHECK_FIXED_INFO(
        UACPI_FIXED_EVENT_POWER_BUTTON,
        FIXED_INFO_ENABLED | UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(power.count == 1);
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_POWER_BUTTON, FIXED_INFO_ENABLED);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    // An event that is not enabled is left alone
    fixed_event_set_status(ACPI_PM1_STS_SLPBTN_STS_MASK);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    CHECK_FIXED_INFO(
        UACPI_FIXED_EVENT_SLEEP_BUTTON, UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK_OK(uacpi_clear_fixed_event(UACPI_FIXED_EVENT_SLEEP_BUTTON));
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_SLEEP_BUTTON, 0);

    CHECK_OK(uacpi_disable_fixed_event(UACPI_FIXED_EVENT_POWER_BUTTON));
    CHECK_FIXED_INFO(
        UACPI_FIXED_EVENT_POWER_BUTTON, UACPI_EVENT_INFO_HAS_HANDLER
    );

    fixed_event_set_status(ACPI_PM1_STS_PWRBTN_STS_MASK);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    CHECK(power.count == 1);

    CHECK_OK(uacpi_enable_fixed_event(UACPI_FIXED_EVENT_POWER_BUTTON));
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(power.count == 2);

    /*
     * Acknowledging an event must not affect any other event that happens to
     * be pending at the same time, be it done by us or by hand.
     */
    fixed_event_set_status(
        ACPI_PM1_STS_PWRBTN_STS_MASK | ACPI_PM1_STS_SLPBTN_STS_MASK
    );
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(power.count == 3);
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_POWER_BUTTON, FIXED_INFO_ENABLED);
    CHECK_FIXED_INFO(
        UACPI_FIXED_EVENT_SLEEP_BUTTON, UACPI_EVENT_INFO_HW_STATUS
    );

    fixed_event_set_status(ACPI_PM1_STS_PWRBTN_STS_MASK);
    CHECK_OK(uacpi_clear_fixed_event(UACPI_FIXED_EVENT_POWER_BUTTON));
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_POWER_BUTTON, FIXED_INFO_ENABLED);
    CHECK_FIXED_INFO(
        UACPI_FIXED_EVENT_SLEEP_BUTTON, UACPI_EVENT_INFO_HW_STATUS
    );

    CHECK_OK(uacpi_clear_fixed_event(UACPI_FIXED_EVENT_SLEEP_BUTTON));
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_SLEEP_BUTTON, 0);

    // The very last fixed event
    CHECK_OK(uacpi_install_fixed_event_handler(
        UACPI_FIXED_EVENT_RTC, log_fixed_event, &rtc
    ));
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_RTC, FIXED_INFO_ENABLED);

    fixed_event_set_status(ACPI_PM1_STS_RTC_STS_MASK);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(rtc.count == 1);
    CHECK(power.count == 3);
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_RTC, FIXED_INFO_ENABLED);

    // More than one event may be pending at once
    fixed_event_set_status(
        ACPI_PM1_STS_PWRBTN_STS_MASK | ACPI_PM1_STS_RTC_STS_MASK
    );
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(power.count == 4);
    CHECK(rtc.count == 2);

    /*
     * The button that has woken us up is not supposed to be delivered as if it
     * was pressed once again. This is not the case for anything else that is
     * pending at the time, e.g. the RTC alarm.
     *
     * Also pretend that the power button didn't make it through the sleep
     * enabled, it's expected to be turned back on since it has a handler.
     */
    fake_io_lower(
        FAKE_PM1A_EVT_BLK + 3, (uint8_t)(ACPI_PM1_EN_PWRBTN_EN_MASK >> 8)
    );
    CHECK_FIXED_INFO(
        UACPI_FIXED_EVENT_POWER_BUTTON, UACPI_EVENT_INFO_HAS_HANDLER
    );

    fixed_event_set_status(
        ACPI_PM1_STS_PWRBTN_STS_MASK | ACPI_PM1_STS_RTC_STS_MASK |
        ACPI_PM1_STS_WAKE_STS_MASK
    );
    CHECK_OK(uacpi_wake_from_sleep_state(UACPI_SLEEP_STATE_S3));
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_POWER_BUTTON, FIXED_INFO_ENABLED);

    // The sleep button has no handler, and so has no business being enabled
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_SLEEP_BUTTON, 0);

    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(power.count == 4);
    CHECK(rtc.count == 3);

    // An actual press of the button is delivered as usual
    fixed_event_set_status(ACPI_PM1_STS_PWRBTN_STS_MASK);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_HANDLED);
    CHECK(power.count == 5);

    // An event is disabled along with the removal of its handler
    CHECK_OK(uacpi_uninstall_fixed_event_handler(
        UACPI_FIXED_EVENT_POWER_BUTTON
    ));
    CHECK_FIXED_INFO(UACPI_FIXED_EVENT_POWER_BUTTON, 0);
    CHECK_STATUS(
        uacpi_enable_fixed_event(UACPI_FIXED_EVENT_POWER_BUTTON),
        UACPI_STATUS_NO_HANDLER
    );

    fixed_event_set_status(ACPI_PM1_STS_PWRBTN_STS_MASK);
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    CHECK(power.count == 5);
    CHECK_OK(uacpi_clear_fixed_event(UACPI_FIXED_EVENT_POWER_BUTTON));

    /*
     * The handler of the RTC is left in place on purpose, it's expected to
     * be taken care of when uACPI is deinitialized.
     */
}

// Expects a FADT that doesn't describe any GPE blocks
void test_gpe_block_without_fadt_gpes(void)
{
    uacpi_namespace_node *gpeb = find_node("\\GPEB");
    uacpi_event_info info;
    uacpi_u64 round;

    CHECK_STATUS(uacpi_gpe_info(UACPI_NULL, 0, &info), UACPI_STATUS_NOT_FOUND);
    CHECK_OK(uacpi_finalize_gpe_initialization());
    CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);

    fake_io_set_write_one_to_clear(GPEB_ADDRESS, GPEB_NUM_REGISTERS);

    /*
     * The SCI is still expected to handle a block that asks for it. Do this
     * more than once to make sure that it also survives the block going away.
     */
    for (round = 1; round <= 2; ++round) {
        CHECK_OK(uacpi_install_gpe_block(
            gpeb, GPEB_ADDRESS, UACPI_ADDRESS_SPACE_SYSTEM_IO,
            GPEB_NUM_REGISTERS, FAKE_SCI_IRQ
        ));

        fake_io_raise(GPEB_ADDRESS, 1 << 1);
        CHECK_OK(uacpi_finalize_gpe_initialization());
        CHECK(eval_integer("\\GPEB.CNT1") == round);
        CHECK_GPE_INFO(gpeb, 0, GPE_INFO_ENABLED);
        CHECK_GPE_INFO(gpeb, 1, GPE_INFO_ENABLED);

        gpe_block_fire(GPEB_ADDRESS, FAKE_SCI_IRQ, 0);
        CHECK(eval_integer("\\GPEB.CNT0") == round);

        CHECK_OK(uacpi_uninstall_gpe_block(gpeb));

        fake_io_raise(GPEB_ADDRESS, 1 << 0);
        CHECK(fake_irq_raise(FAKE_SCI_IRQ) == UACPI_INTERRUPT_NOT_HANDLED);
    }
}

/*
 * Resets the state of uACPI with work still in flight, which is expected to
 * get a chance to complete before anything that it relies upon is gone.
 */
static void do_test_state_reset_vs_work(bool has_gpes)
{
    uacpi_namespace_node *dev0 = find_node("\\DEV0");
    notify_log_t log = { 0 };
    size_t expected_count = 1;

    CHECK_OK(uacpi_install_notify_handler(dev0, notify_a, &log));
    CHECK_OK(uacpi_finalize_gpe_initialization());

    work_threads_start();
    work_hold();

    // A notification that was already queued
    CHECK_OK(uacpi_execute_simple(UACPI_NULL, "\\NTF0"));

    // A GPE handler that hasn't even had a chance to produce one yet
    if (has_gpes) {
        gpe_fire(0);
        expected_count++;
    }

    uacpi_state_reset();
    CHECK(log.count == expected_count);

    work_threads_stop();
}

void test_state_reset_vs_gpe_work(void)
{
    do_test_state_reset_vs_work(true);
}

// Expects a FADT that doesn't describe any GPE blocks
void test_state_reset_vs_notifications(void)
{
    do_test_state_reset_vs_work(false);
}
