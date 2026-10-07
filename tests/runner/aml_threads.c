#include "helpers.h"
#include "os.h"
#include "tests.h"
#include <inttypes.h>
#include <stdlib.h>
#include <uacpi/namespace.h>
#include <uacpi/notify.h>
#include <uacpi/uacpi.h>

/*
 * AML has no way of starting a thread, so that's what we do on its behalf:
 * whenever an object is notified, its WORK method is executed on a thread of
 * its own, with the value of the notification as the only argument.
 *
 * This is all that it takes for a test to be able to do whatever it wants with
 * an object while someone else is in the middle of using it.
 */
struct aml_thread {
    thread_t thread;
    struct aml_thread *next;
    uacpi_namespace_node *node;
    uacpi_u64 value;
    uacpi_status status;
};

static struct aml_thread *aml_threads;
static mutex_t aml_threads_lock;

static void aml_thread_entry(void *opaque)
{
    struct aml_thread *thread = opaque;
    uacpi_object *arg;
    uacpi_object_array args;

    arg = uacpi_object_create_integer(thread->value);
    args.objects = &arg;
    args.count = 1;

    thread->status = uacpi_eval(thread->node, "WORK", &args, UACPI_NULL);
    uacpi_object_unref(arg);
}

static uacpi_status aml_thread_start(
    uacpi_handle ctx, uacpi_namespace_node *node, uacpi_u64 value
)
{
    struct aml_thread *thread;

    UACPI_UNUSED(ctx);

    thread = do_calloc(1, sizeof(*thread));
    thread->node = node;
    thread->value = value;

    mutex_lock(&aml_threads_lock);

    thread->next = aml_threads;
    aml_threads = thread;
    thread_create(&thread->thread, aml_thread_entry, thread);

    mutex_unlock(&aml_threads_lock);
    return UACPI_STATUS_OK;
}

static struct aml_thread *aml_threads_take(void)
{
    struct aml_thread *threads;

    // Make sure that every notification so far was delivered
    ensure_ok_status(uacpi_kernel_wait_for_work_completion());

    mutex_lock(&aml_threads_lock);
    threads = aml_threads;
    aml_threads = NULL;
    mutex_unlock(&aml_threads_lock);

    return threads;
}

void test_aml_with_threads(void)
{
    uacpi_namespace_node *root = uacpi_namespace_root();
    struct aml_thread *threads, *thread;
    uacpi_status st, thread_st = UACPI_STATUS_OK;
    uacpi_u64 ret = 0;

    mutex_init(&aml_threads_lock);

    st = uacpi_install_notify_handler(root, aml_thread_start, NULL);
    ensure_ok_status(st);

    /*
     * This also gets us terminated if the test doesn't finish in a reasonable
     * time, which is what happens if any of the threads is stuck for good.
     */
    work_threads_start();

    st = uacpi_eval_simple_integer(NULL, "\\TEST", &ret);

    // A thread might start more threads, so go on until there's none left
    while ((threads = aml_threads_take()) != NULL) {
        while (threads != NULL) {
            thread = threads;
            threads = thread->next;

            thread_join(&thread->thread);
            if (thread->status != UACPI_STATUS_OK)
                thread_st = thread->status;

            free(thread);
        }
    }

    work_threads_stop();
    mutex_free(&aml_threads_lock);

    ensure_ok_status(st);
    ensure_ok_status(thread_st);
    ensure_ok_status(uacpi_uninstall_notify_handler(root, aml_thread_start));

    if (!ret)
        error("\\TEST has failed");
}
