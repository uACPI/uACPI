#include <uacpi/internal/opregion.h>
#include <uacpi/kernel_api.h>
#include <uacpi/internal/namespace.h>
#include <uacpi/uacpi.h>
#include <uacpi/internal/stdlib.h>
#include <uacpi/internal/log.h>

void uacpi_trace_region_error(
    uacpi_namespace_node *node, uacpi_char *message, uacpi_status ret
)
{
    const uacpi_char *path;
    uacpi_operation_region *op_region;

    path = uacpi_namespace_node_generate_absolute_path(node);
    op_region = uacpi_namespace_node_get_object(node)->op_region;

    uacpi_warn(
        "%s operation region %s@%p: %s\n",
        message, path, op_region, uacpi_status_to_string(ret)
    );
    uacpi_kernel_free((void*)path);
}

#define UACPI_TRACE_REGION_IO

void uacpi_trace_region_io(
    uacpi_namespace_node *node, uacpi_region_op op,
    uacpi_u64 offset, uacpi_u8 byte_size, uacpi_u64 ret
)
{
#ifdef UACPI_TRACE_REGION_IO
    const uacpi_char *path;
    uacpi_operation_region *op_region;
    const uacpi_char *type_str;

    switch (op) {
    case UACPI_REGION_OP_READ:
        type_str = "read from";
        break;
    case UACPI_REGION_OP_WRITE:
        type_str = "write to";
        break;
    default:
        type_str = "<INVALID-OP>";
    }

    op_region = uacpi_namespace_node_get_object(node)->op_region;
    path = uacpi_namespace_node_generate_absolute_path(node);

    uacpi_trace(
        "%s [%s] (%d bytes) %s[0x%016"UACPI_PRIX64"] = 0x%"PRIX64"\n",
        type_str, path, byte_size,
        uacpi_address_space_to_string(op_region->space),
        offset, ret
    );

    uacpi_kernel_free((void*)path);
#else
    UACPI_UNUSED(op);
    UACPI_UNUSED(node);
    UACPI_UNUSED(offset);
    UACPI_UNUSED(byte_size);
    UACPI_UNUSED(ret);
#endif
}

static uacpi_bool space_needs_reg(enum uacpi_address_space space)
{
    if (space == UACPI_ADDRESS_SPACE_SYSTEM_MEMORY ||
        space == UACPI_ADDRESS_SPACE_SYSTEM_IO)
        return UACPI_FALSE;

    return UACPI_TRUE;
}

static uacpi_status region_run_reg(
    uacpi_namespace_node *node, uacpi_u8 connection_code
)
{
    uacpi_status ret;
    uacpi_args method_args;
    uacpi_object *args[2];

    args[0] = uacpi_create_object(UACPI_OBJECT_INTEGER);
    if (uacpi_unlikely(args[0] == UACPI_NULL))
        return UACPI_STATUS_OUT_OF_MEMORY;

    args[1] = uacpi_create_object(UACPI_OBJECT_INTEGER);
    if (uacpi_unlikely(args[1] == UACPI_NULL)) {
        uacpi_object_unref(args[0]);
        return UACPI_STATUS_OUT_OF_MEMORY;
    }

    args[0]->integer = uacpi_namespace_node_get_object(node)->op_region->space;
    args[1]->integer = connection_code;
    method_args.objects = args;
    method_args.count = 2;

    ret = uacpi_eval(node->parent, "_REG", &method_args, UACPI_NULL);
    if (uacpi_unlikely_error(ret && ret != UACPI_STATUS_NOT_FOUND))
        uacpi_trace_region_error(node, "error during _REG execution for", ret);

    uacpi_object_unref(args[0]);
    uacpi_object_unref(args[1]);
    return ret;
}

uacpi_address_space_handlers *uacpi_node_get_address_space_handlers(
    uacpi_namespace_node *node
)
{
    uacpi_object *object;

    object = uacpi_namespace_node_get_object(node);
    if (uacpi_unlikely(object == UACPI_NULL))
        return UACPI_NULL;

    switch (object->type) {
    default:
        /*
         * Even though the '\' object doesn't have its type set to
         * UACPI_OBJECT_DEVICE, it is one.
         * See namespace.c:make_object_for_predefined for reasoning.
         */
        if (node != uacpi_namespace_root() ||
            object->type != UACPI_OBJECT_UNINITIALIZED)
            return UACPI_NULL;
        UACPI_FALLTHROUGH;
    case UACPI_OBJECT_DEVICE:
    case UACPI_OBJECT_PROCESSOR:
    case UACPI_OBJECT_THERMAL_ZONE:
        return object->address_space_handlers;
    }
}

static uacpi_address_space_handler *find_handler(
    uacpi_address_space_handlers *handlers,
    enum uacpi_address_space space
)
{
    uacpi_address_space_handler *handler = handlers->head;

    while (handler) {
        if (handler->space == space)
            return handler;

        handler = handler->next;
    }

    return UACPI_NULL;
}

static uacpi_operation_region *find_previous_region_link(
    uacpi_operation_region *region
)
{
    uacpi_address_space_handler *handler = region->handler;
    uacpi_operation_region *parent = handler->regions;

    if (parent == region)
        // This is the last attached region, it has no previous link
        return region;

    while (parent->next != region) {
        parent = parent->next;

        if (uacpi_unlikely(parent == UACPI_NULL))
            return UACPI_NULL;
    }

    return parent;
}

uacpi_status uacpi_opregion_attach(uacpi_namespace_node *node)
{
    uacpi_operation_region *region;
    uacpi_address_space_handler *handler;
    uacpi_status ret;
    uacpi_region_attach_data attach_data = { 0 };

    if (uacpi_namespace_node_is_dangling(node))
        return UACPI_STATUS_NAMESPACE_NODE_DANGLING;

    region = uacpi_namespace_node_get_object(node)->op_region;
    if (region->handler == UACPI_NULL)
        return UACPI_STATUS_NO_HANDLER;
    if (region->state_flags & UACPI_OP_REGION_STATE_ATTACHED)
        return UACPI_STATUS_OK;

    handler = region->handler;
    attach_data.region_node = node;
    attach_data.handler_context = handler->user_context;

    ret = handler->callback(UACPI_REGION_OP_ATTACH, &attach_data);
    if (uacpi_unlikely_error(ret)) {
        uacpi_trace_region_error(node, "failed to attach a handler to", ret);
        return ret;
    }

    region->state_flags |= UACPI_OP_REGION_STATE_ATTACHED;
    region->user_context = attach_data.out_region_context;
    return ret;
}

static void region_install_handler(uacpi_namespace_node *node,
                                   uacpi_address_space_handler *handler)
{
    uacpi_operation_region *region;

    region = uacpi_namespace_node_get_object(node)->op_region;
    region->handler = handler;
    uacpi_shareable_ref(handler);

    region->next = handler->regions;
    handler->regions = region;
}

void uacpi_opregion_uninstall_handler(uacpi_namespace_node *node)
{
    uacpi_address_space_handler *handler;
    uacpi_operation_region *region, *link;

    region = uacpi_namespace_node_get_object(node)->op_region;
    handler = region->handler;

    if (handler == UACPI_NULL)
        return;

    link = find_previous_region_link(region);
    if (uacpi_unlikely(link == UACPI_NULL)) {
        uacpi_error("operation region @%p not in the handler@%p list(?)\n",
                    region, handler);
        goto out;
    } else if (link == region) {
        link = link->next;
        handler->regions = link;
    } else {
        link->next = region->next;
    }

out:
    if (region->state_flags & UACPI_OP_REGION_STATE_ATTACHED) {
        uacpi_status ret;
        uacpi_region_detach_data detach_data = {
            .region_node = node,
            .region_context = region->user_context,
            .handler_context = handler->user_context,
        };

        ret = handler->callback(UACPI_REGION_OP_DETACH, &detach_data);
        if (uacpi_unlikely_error(ret)) {
            uacpi_trace_region_error(
                node, "error during handler detach for", ret
            );
        }
    }

    if (region->state_flags & UACPI_OP_REGION_STATE_REG_EXECUTED)
        region_run_reg(node, ACPI_REG_DISCONNECT);

    uacpi_address_space_handler_unref(region->handler);
    region->handler = UACPI_NULL;
    region->state_flags &= ~(UACPI_OP_REGION_STATE_ATTACHED |
                             UACPI_OP_REGION_STATE_REG_EXECUTED);
}

enum opregion_iter_action {
    OPREGION_ITER_ACTION_UNINSTALL,
    OPREGION_ITER_ACTION_INSTALL,
};

struct opregion_iter_ctx {
    enum opregion_iter_action action;
    uacpi_address_space_handler *handler;
};

static enum uacpi_ns_iteration_decision do_install_or_uninstall_handler(
    uacpi_handle opaque, uacpi_namespace_node *node
)
{
    struct opregion_iter_ctx *ctx = opaque;
    uacpi_address_space_handlers *handlers;
    uacpi_object *object;

    object = uacpi_namespace_node_get_object(node);
    if (object->type == UACPI_OBJECT_OPERATION_REGION) {
        uacpi_operation_region *region = object->op_region;

        if (region->space != ctx->handler->space)
            return UACPI_NS_ITERATION_DECISION_CONTINUE;

        if (ctx->action == OPREGION_ITER_ACTION_INSTALL) {
            if (region->handler)
                uacpi_opregion_uninstall_handler(node);

            region_install_handler(node, ctx->handler);
        } else {
            if (uacpi_unlikely(region->handler != ctx->handler)) {
                uacpi_trace_region_error(
                    node, "handler mismatch for",
                    UACPI_STATUS_INTERNAL_ERROR
                );
                return UACPI_NS_ITERATION_DECISION_CONTINUE;
            }

            uacpi_opregion_uninstall_handler(node);
        }

        return UACPI_NS_ITERATION_DECISION_CONTINUE;
    }

    handlers = uacpi_node_get_address_space_handlers(node);
    if (handlers == UACPI_NULL)
        return UACPI_NS_ITERATION_DECISION_CONTINUE;

    // Device already has a handler for this space installed
    if (find_handler(handlers, ctx->handler->space) != UACPI_NULL)
        return UACPI_NS_ITERATION_DECISION_NEXT_PEER;

    return UACPI_NS_ITERATION_DECISION_CONTINUE;
}

void uacpi_opregion_reg(uacpi_namespace_node *node)
{
    uacpi_operation_region *region;

    region = uacpi_namespace_node_get_object(node)->op_region;
    if (region->state_flags & UACPI_OP_REGION_STATE_REG_EXECUTED)
        return;

    if (!space_needs_reg(region->space))
        return;

    if (region_run_reg(node, ACPI_REG_CONNECT) == UACPI_STATUS_OK)
        region->state_flags |= UACPI_OP_REGION_STATE_REG_EXECUTED;
}

struct reg_run_ctx {
    uacpi_u8 space;
    uacpi_u8 connection_code;
    uacpi_size reg_executed;
    uacpi_size reg_errors;
};

enum uacpi_ns_iteration_decision do_run_reg(
    void *opaque, uacpi_namespace_node *node
)
{
    struct reg_run_ctx *ctx = opaque;
    uacpi_object *object;
    uacpi_operation_region *region;
    uacpi_status ret;

    object = uacpi_namespace_node_get_object(node);
    if (object->type != UACPI_OBJECT_OPERATION_REGION)
        return UACPI_NS_ITERATION_DECISION_CONTINUE;

    region = object->op_region;

    if (region->space != ctx->space ||
        (region->state_flags & UACPI_OP_REGION_STATE_REG_EXECUTED))
        return UACPI_NS_ITERATION_DECISION_CONTINUE;

    if (region->handler == UACPI_NULL &&
        ctx->connection_code != ACPI_REG_DISCONNECT)
        return UACPI_NS_ITERATION_DECISION_CONTINUE;

    ret = region_run_reg(node, ctx->connection_code);
    if (ret == UACPI_STATUS_NOT_FOUND)
        return UACPI_NS_ITERATION_DECISION_CONTINUE;

    ctx->reg_executed++;

    if (uacpi_unlikely_error(ret)) {
        ctx->reg_errors++;
        return UACPI_NS_ITERATION_DECISION_CONTINUE;
    }

    region->state_flags |= UACPI_OP_REGION_STATE_REG_EXECUTED;
    return UACPI_NS_ITERATION_DECISION_CONTINUE;
}

uacpi_status uacpi_reg_all_opregions(
    uacpi_namespace_node *device_node,
    enum uacpi_address_space space
)
{
    uacpi_address_space_handlers *handlers;
    uacpi_address_space_handler *this_handler;
    struct reg_run_ctx ctx = {
        .space = space,
        .connection_code = ACPI_REG_CONNECT,
    };

    if (!space_needs_reg(space))
        return UACPI_STATUS_OK;

    handlers = uacpi_node_get_address_space_handlers(device_node);
    if (uacpi_unlikely(handlers == UACPI_NULL))
        return UACPI_STATUS_INVALID_ARGUMENT;

    this_handler = find_handler(handlers, space);
    if (uacpi_unlikely(this_handler == UACPI_NULL))
        return UACPI_STATUS_NO_HANDLER;

    uacpi_namespace_for_each_node_depth_first(
        device_node->child, do_run_reg, &ctx
    );

    uacpi_trace(
        "activated all '%s' opregions controlled by '%.4s', "
        "%zu _REG() calls (%zu errors)\n", uacpi_address_space_to_string(space),
        device_node->name.text, ctx.reg_executed, ctx.reg_errors
    );
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_install_address_space_handler(
    uacpi_namespace_node *device_node, enum uacpi_address_space space,
    uacpi_region_handler handler, uacpi_handle handler_context
)
{
    uacpi_address_space_handlers *handlers;
    uacpi_address_space_handler *this_handler, *new_handler;
    struct opregion_iter_ctx iter_ctx;

    handlers = uacpi_node_get_address_space_handlers(device_node);
    if (uacpi_unlikely(handlers == UACPI_NULL))
        return UACPI_STATUS_INVALID_ARGUMENT;

    this_handler = find_handler(handlers, space);
    if (this_handler != UACPI_NULL)
        return UACPI_STATUS_ALREADY_EXISTS;

    new_handler = uacpi_kernel_alloc(sizeof(*new_handler));
    if (new_handler == UACPI_NULL)
        return UACPI_STATUS_OUT_OF_MEMORY;
    uacpi_shareable_init(new_handler);

    new_handler->next = handlers->head;
    new_handler->space = space;
    new_handler->user_context = handler_context;
    new_handler->callback = handler;
    new_handler->regions = UACPI_NULL;
    handlers->head = new_handler;

    iter_ctx.handler = new_handler;
    iter_ctx.action = OPREGION_ITER_ACTION_INSTALL;

    uacpi_namespace_for_each_node_depth_first(
        device_node->child, do_install_or_uninstall_handler, &iter_ctx
    );

    if (!space_needs_reg(space))
        return UACPI_STATUS_OK;

     /*
      * Installing an early address space handler, obviously not possible to
      * execute any _REG methods here. Just return and hope that it is either
      * a global address space handler, or a handler installed by a user who
      * will run uacpi_reg_all_opregions manually after loading/initializing
      * the namespace.
      */
    if (g_uacpi_rt_ctx.init_level < UACPI_INIT_LEVEL_NAMESPACE_LOADED)
        return UACPI_STATUS_OK;

    /*
     * _REG methods for global address space handlers (installed to root)
     * get called during the namespace initialization, no reason
     * to call them here manually as that will be done later by init code
     * anyway. Just delay that work until later.
     */
    if (device_node == uacpi_namespace_root() &&
        g_uacpi_rt_ctx.init_level == UACPI_INIT_LEVEL_NAMESPACE_LOADED)
        return UACPI_STATUS_OK;

    // Init level is NAMESPACE_INITIALIZED, so we can safely run _REG now
    return uacpi_reg_all_opregions(device_node, space);
}

uacpi_status uacpi_uninstall_address_space_handler(
    uacpi_namespace_node *device_node,
    enum uacpi_address_space space
)
{
    uacpi_address_space_handlers *handlers;
    uacpi_address_space_handler *handler, *prev_handler;
    struct opregion_iter_ctx iter_ctx;

    handlers = uacpi_node_get_address_space_handlers(device_node);
    if (uacpi_unlikely(handlers == UACPI_NULL))
        return UACPI_STATUS_INVALID_ARGUMENT;

    handler = find_handler(handlers, space);
    if (uacpi_unlikely(handler == UACPI_NULL))
        return UACPI_STATUS_NO_HANDLER;

    iter_ctx.handler = handler;
    iter_ctx.action = OPREGION_ITER_ACTION_UNINSTALL;

    uacpi_namespace_for_each_node_depth_first(
        device_node->child, do_install_or_uninstall_handler, &iter_ctx
    );

    prev_handler = handlers->head;

    // Are we the last linked handler?
    if (prev_handler == handler) {
        handlers->head = handler->next;
        goto out;
    }

    // Nope, we're somewhere in the middle. Do a search.
    while (prev_handler) {
        if (prev_handler->next == handler) {
            prev_handler->next = handler->next;
            goto out;
        }

        prev_handler = prev_handler->next;
    }

out:
    uacpi_address_space_handler_unref(handler);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_opregion_find_and_install_handler(
    uacpi_namespace_node *node
)
{
    uacpi_namespace_node *parent = node->parent;
    uacpi_address_space_handlers *handlers;
    uacpi_address_space_handler *handler;
    uacpi_u8 space;

    space = uacpi_namespace_node_get_object(node)->op_region->space;

    while (parent) {
        handlers = uacpi_node_get_address_space_handlers(parent);
        if (handlers != UACPI_NULL) {
            handler = find_handler(handlers, space);

            if (handler != UACPI_NULL) {
                region_install_handler(node, handler);
                return UACPI_STATUS_OK;
            }
        }

        parent = parent->parent;
    }

    return UACPI_STATUS_NOT_FOUND;
}