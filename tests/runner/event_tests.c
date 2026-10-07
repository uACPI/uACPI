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
