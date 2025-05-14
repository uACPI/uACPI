#include "argparser.h"
#include "helpers.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uacpi/acpi.h>
#include <uacpi/context.h>
#include <uacpi/event.h>
#include <uacpi/log.h>
#include <uacpi/namespace.h>
#include <uacpi/notify.h>
#include <uacpi/opregion.h>
#include <uacpi/osi.h>
#include <uacpi/platform/types.h>
#include <uacpi/resources.h>
#include <uacpi/status.h>
#include <uacpi/tables.h>
#include <uacpi/types.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>

void run_resource_tests(void);
void test_object_api(void);
void test_address_spaces(void);
void interface_cleanup(void);

static uacpi_object_type string_to_object_type(const char *str)
{
    if (strcmp(str, "int") == 0)
        return UACPI_OBJECT_INTEGER;
    if (strcmp(str, "str") == 0)
        return UACPI_OBJECT_STRING;

    error("Unsupported type for validation: %s", str);
    return UACPI_OBJECT_UNINITIALIZED;
}

static void validate_ret_against_expected(
    uacpi_object *obj, uacpi_object_type expected_type, const char *expected_val
)
{
    uacpi_object_type type = uacpi_object_get_type(obj);

    if (type != expected_type)
        error(
            "returned type '%s' doesn't match expected '%s",
            uacpi_object_type_to_string(expected_type),
            uacpi_object_type_to_string(type)
        );

    switch (type) {
    case UACPI_OBJECT_INTEGER: {
        uacpi_u64 expected_int = strtoull(expected_val, NULL, 0);
        uacpi_u64 actual_int;

        uacpi_object_get_integer(obj, &actual_int);

        if (expected_int != actual_int)
            error(
                "returned value '%" PRIu64 "' doesn't match expected '%" PRIu64
                "'", actual_int, expected_int
            );

        break;
    }
    case UACPI_OBJECT_STRING: {
        uacpi_data_view view;
        const char *actual_str;

        uacpi_object_get_string_or_buffer(obj, &view);
        actual_str = view.text;

        if (strcmp(expected_val, actual_str) != 0)
            error(
                "returned value '%s' doesn't match expected '%s'",
                actual_str, expected_val
            );

        break;
    }
    default:
        abort();
    }
}

static void nested_printf(uacpi_u32 depth, const char *fmt, ...)
{
    va_list va;
    size_t padding = depth * 4;

    while (padding-- > 0)
        printf(" ");

    va_start(va, fmt);
    vprintf(fmt, va);
    va_end(va);
}

static void dump_resources(
    uacpi_u32 depth, uacpi_namespace_node *node,
    uacpi_status (*cb)(uacpi_namespace_node *, uacpi_resources **),
    const char *name
)
{
    uacpi_resources *res;
    uacpi_status ret = cb(node, &res);

    if (ret == UACPI_STATUS_OK) {
        // TODO: dump resources here
        nested_printf(depth, "  %s: <%u bytes>\n", name, res->length);
        uacpi_free_resources(res);
    } else if (ret != UACPI_STATUS_NOT_FOUND)
        nested_printf(
            depth, "  %s: unable to evaluate (%s)\n", name,
            uacpi_status_to_string(ret)
        );
}

static uacpi_iteration_decision dump_one_node(
    void *ptr, uacpi_namespace_node *node, uacpi_u32 depth
)
{
    struct uacpi_namespace_node_info *info;
    uacpi_status ret = uacpi_get_namespace_node_info(node, &info);
    const char *path;

    UACPI_UNUSED(ptr);

    if (uacpi_unlikely_error(ret)) {
        uacpi_object_name name = uacpi_namespace_node_name(node);

        fprintf(
            stderr, "unable to get node %.4s info: %s\n", name.text,
            uacpi_status_to_string(ret)
        );
        exit(1);
    }

    path = uacpi_namespace_node_generate_absolute_path(node);
    nested_printf(
        depth, "%s [%s]", path, uacpi_object_type_to_string(info->type)
    );
    uacpi_free_absolute_path(path);

    if (info->type == UACPI_OBJECT_METHOD)
        printf(" (%d args)", info->num_params);

    if (info->flags)
        printf(" {\n");

    if (info->flags)
        nested_printf(depth, "    _ADR: %016" PRIX64 "\n", info->adr);

    if (info->flags & UACPI_NS_NODE_INFO_HAS_HID)
        nested_printf(depth, "    _HID: %s\n", info->hid.value);

    if (info->flags & UACPI_NS_NODE_INFO_HAS_CID) {
        size_t i;

        nested_printf(depth, "    _CID: ");
        for (i = 0; i < info->cid.num_ids; ++i)
            printf("%s ", info->cid.ids[i].value);

        printf("\n");
    }

    if (info->flags & UACPI_NS_NODE_INFO_HAS_UID)
        nested_printf(depth, "    _UID: %s\n", info->uid.value);

    if (info->flags & UACPI_NS_NODE_INFO_HAS_CLS)
        nested_printf(depth, "    _CLS: %s\n", info->cls.value);

    if (info->flags & UACPI_NS_NODE_INFO_HAS_SXD)
        nested_printf(
            depth, "  _SxD: S1->D%d S2->D%d S3->D%d S4->D%d\n", info->sxd[0],
            info->sxd[1], info->sxd[2], info->sxd[3]
        );

    if (info->flags & UACPI_NS_NODE_INFO_HAS_SXW)
        nested_printf(
            depth, "  _SxW: S0->D%d S1->D%d S2->D%d S3->D%d S4->D%d\n",
            info->sxw[0], info->sxw[1], info->sxw[2], info->sxw[3], info->sxw[4]
        );

    if (info->flags) {
        if (info->type == UACPI_OBJECT_DEVICE) {
            dump_resources(depth, node, uacpi_get_current_resources, "_CRS");
            dump_resources(depth, node, uacpi_get_possible_resources, "_PRS");
        }

        nested_printf(depth, "}\n");
    } else
        printf("\n");

    uacpi_free_namespace_node_info(info);
    return UACPI_ITERATION_DECISION_CONTINUE;
}

static void enumerate_namespace(void)
{
    uacpi_namespace_node *root = uacpi_namespace_root();

    dump_one_node(NULL, root, 0);
    uacpi_namespace_for_each_child_simple(root, dump_one_node, NULL);
}

/*
 * DefinitionBlock ("x.aml", "SSDT", 1, "uTEST", "OVERRIDE", 0xF0F0F0F0)
 * {
 *     Name (VAL, "TestRunner")
 * }
 */
static uint8_t table_override[] = {
    0x53, 0x53, 0x44, 0x54, 0x35, 0x00, 0x00, 0x00,
    0x01, 0xa1, 0x75, 0x54, 0x45, 0x53, 0x54, 0x00,
    0x4f, 0x56, 0x45, 0x52, 0x52, 0x49, 0x44, 0x45,
    0xf0, 0xf0, 0xf0, 0xf0, 0x49, 0x4e, 0x54, 0x4c,
    0x25, 0x09, 0x20, 0x20, 0x08, 0x56, 0x41, 0x4c,
    0x5f, 0x0d, 0x54, 0x65, 0x73, 0x74, 0x52, 0x75,
    0x6e, 0x6e, 0x65, 0x72, 0x00
};

/*
 * DefinitionBlock ("x.aml", "SSDT", 1, "uTEST", "RUNRIDTB", 0xF0F0F0F0)
 * {
 *     Name (\_SI.TID, "uACPI")
 *     Printf("TestRunner ID SSDT loaded!")
 * }
 */
static uint8_t runner_id_table[] = {
    0x53, 0x53, 0x44, 0x54, 0x55, 0x00, 0x00, 0x00,
    0x01, 0x45, 0x75, 0x54, 0x45, 0x53, 0x54, 0x00,
    0x52, 0x55, 0x4e, 0x52, 0x49, 0x44, 0x54, 0x42,
    0xf0, 0xf0, 0xf0, 0xf0, 0x49, 0x4e, 0x54, 0x4c,
    0x25, 0x09, 0x20, 0x20, 0x08, 0x5c, 0x2e, 0x5f,
    0x53, 0x49, 0x5f, 0x54, 0x49, 0x44, 0x5f, 0x0d,
    0x75, 0x41, 0x43, 0x50, 0x49, 0x00, 0x70, 0x0d,
    0x54, 0x65, 0x73, 0x74, 0x52, 0x75, 0x6e, 0x6e,
    0x65, 0x72, 0x20, 0x49, 0x44, 0x20, 0x53, 0x53,
    0x44, 0x54, 0x20, 0x6c, 0x6f, 0x61, 0x64, 0x65,
    0x64, 0x21, 0x00, 0x5b, 0x31
};

static uacpi_table_installation_disposition handle_table_install(
    struct acpi_sdt_hdr *hdr, uacpi_u64 *out_override
)
{
    if (!strncmp(hdr->oem_table_id, "DENYTABL", sizeof(hdr->oem_table_id)))
        return UACPI_TABLE_INSTALLATION_DISPOSITON_DENY;

    if (strncmp(hdr->oem_table_id, "OVERTABL", sizeof(hdr->oem_table_id)))
        return UACPI_TABLE_INSTALLATION_DISPOSITON_ALLOW;

    *out_override = (uacpi_virt_addr)table_override;
    return UACPI_TABLE_INSTALLATION_DISPOSITON_VIRTUAL_OVERRIDE;
}

static uacpi_status handle_notify(
    uacpi_handle handle, uacpi_namespace_node *node, uacpi_u64 value
)
{
    const char *path = uacpi_namespace_node_generate_absolute_path(node);

    UACPI_UNUSED(handle);

    printf("Received a notification from %s %" PRIx64 "\n", path, value);

    free((void*)path);
    return UACPI_STATUS_OK;
}

static uacpi_status handle_ec(uacpi_region_op op, uacpi_handle op_data)
{
    switch (op) {
    case UACPI_REGION_OP_READ: {
        uacpi_region_rw_data *rw_data = (uacpi_region_rw_data*)op_data;

        rw_data->value = 0;
        UACPI_FALLTHROUGH;
    }
    case UACPI_REGION_OP_ATTACH:
    case UACPI_REGION_OP_DETACH:
    case UACPI_REGION_OP_WRITE:
        return UACPI_STATUS_OK;
    default:
        return UACPI_STATUS_INVALID_ARGUMENT;
    }
}

static uacpi_interrupt_ret handle_gpe(
    uacpi_handle handle, uacpi_namespace_node *node, uint16_t idx
)
{
    UACPI_UNUSED(handle);
    UACPI_UNUSED(node);
    UACPI_UNUSED(idx);

    return UACPI_INTERRUPT_HANDLED | UACPI_GPE_REENABLE;
}

static void run_test(
    const char *dsdt_path, const vector_t *ssdt_paths,
    uacpi_object_type expected_type, const char *expected_value,
    bool dump_namespace
)
{
    static uint8_t early_table_buf[4096];
    struct acpi_rsdp rsdp = { 0 };
    struct full_xsdt *xsdt = make_xsdt(&rsdp, dsdt_path, ssdt_paths);
    uacpi_status st;
    uacpi_table tbl;
    bool is_test_mode;
    uacpi_object *ret = NULL;

    g_rsdp = (uacpi_phys_addr)((uintptr_t)&rsdp);

    st = uacpi_setup_early_table_access(
        early_table_buf, sizeof(early_table_buf)
    );
    ensure_ok_status(st);

    st = uacpi_table_find_by_signature(ACPI_DSDT_SIGNATURE, &tbl);
    ensure_ok_status(st);

    if (strncmp(tbl.hdr->signature, ACPI_DSDT_SIGNATURE, 4) != 0)
        error("broken early table access!");

    st = uacpi_table_unref(&tbl);
    ensure_ok_status(st);

    st = uacpi_initialize(UACPI_FLAG_NO_ACPI_MODE);
    ensure_ok_status(st);

    /*
     * Go through all AML tables and manually bump their reference counts here
     * so that they're mapped before the call to uacpi_namespace_load(). The
     * reason we need this is to disambiguate calls to uacpi_kernel_map() with
     * a synthetic physical address (that is actually a virtual address for
     * tables that we constructed earlier) or a real physical address that comes
     * from some operation region or any other AML code or action.
     */
    uacpi_table_find_by_signature(ACPI_DSDT_SIGNATURE, &tbl);

    st = uacpi_table_find_by_signature(ACPI_SSDT_SIGNATURE, &tbl);
    while (st == UACPI_STATUS_OK) {
        uacpi_table_ref(&tbl);
        st = uacpi_table_find_next_with_same_signature(&tbl);
    }

    g_expect_virtual_addresses = false;

    st = uacpi_install_notify_handler(
        uacpi_namespace_root(), handle_notify, NULL
    );
    ensure_ok_status(st);

    st = uacpi_set_table_installation_handler(handle_table_install);
    ensure_ok_status(st);

    st = uacpi_install_interface("TestRunner", UACPI_INTERFACE_KIND_FEATURE);
    ensure_ok_status(st);

    st = uacpi_uninstall_interface("Windows 2006");
    ensure_ok_status(st);

    st = uacpi_uninstall_interface("Windows 2006");
    if (st != UACPI_STATUS_NOT_FOUND)
        error("couldn't uninstall interface");

    st = uacpi_enable_host_interface(UACPI_HOST_INTERFACE_3_0_THERMAL_MODEL);
    ensure_ok_status(st);

    st = uacpi_enable_host_interface(UACPI_HOST_INTERFACE_MODULE_DEVICE);
    ensure_ok_status(st);

    is_test_mode = expected_type != UACPI_OBJECT_UNINITIALIZED;
    if (is_test_mode) {
        st = uacpi_table_install(runner_id_table, NULL);
        ensure_ok_status(st);
    }

    st = uacpi_namespace_load();
    ensure_ok_status(st);

    if (is_test_mode) {
        uacpi_object *runner_id = UACPI_NULL;
        uacpi_data_view view;

        st = uacpi_eval_typed(
            UACPI_NULL, "\\_SI.TID", UACPI_NULL, UACPI_OBJECT_STRING_BIT,
            &runner_id
        );
        ensure_ok_status(st);

        st = uacpi_object_get_string_or_buffer(runner_id, &view);
        ensure_ok_status(st);

        if (strcmp(view.text, "uACPI") != 0)
            error("invalid test runner id");
        uacpi_object_unref(runner_id);
    }

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_EMBEDDED_CONTROLLER,
        handle_ec, NULL
    );
    ensure_ok_status(st);

    st = uacpi_install_gpe_handler(
        UACPI_NULL, 123, UACPI_GPE_TRIGGERING_EDGE, handle_gpe, NULL
    );
    ensure_ok_status(st);

    st = uacpi_enable_gpe(UACPI_NULL, 123);
    ensure_ok_status(st);

    st = uacpi_disable_gpe(UACPI_NULL, 123);
    ensure_ok_status(st);

    st = uacpi_uninstall_gpe_handler(UACPI_NULL, 123, handle_gpe);
    ensure_ok_status(st);

    st = uacpi_namespace_initialize();
    ensure_ok_status(st);

    if (dump_namespace)
        enumerate_namespace();

    if (!is_test_mode)
        goto done;

    if (strcmp(expected_value, "check-object-api-works") == 0) {
        test_object_api();
        goto done;
    }

    if (strcmp(expected_value, "check-address-spaces-work") == 0) {
        test_address_spaces();
        goto done;
    }

    st = uacpi_eval(UACPI_NULL, "\\MAIN", UACPI_NULL, &ret);

    ensure_ok_status(st);
    if (ret == NULL)
        error("\\MAIN didn't return a value");
    validate_ret_against_expected(ret, expected_type, expected_value);

    uacpi_object_unref(ret);
done:
    uacpi_state_reset();
    delete_xsdt(xsdt, ssdt_paths->count);
    interface_cleanup();
}

static uacpi_log_level log_level_from_string(const char *arg)
{
    static struct {
        const char *str;
        uacpi_log_level level;
    } log_levels[] = {
        { "debug", UACPI_LOG_DEBUG },
        { "trace", UACPI_LOG_TRACE },
        { "info", UACPI_LOG_INFO },
        { "warning", UACPI_LOG_WARN },
        { "error", UACPI_LOG_ERROR },
    };
    size_t i;

    for (i = 0; i < UACPI_ARRAY_SIZE(log_levels); i++)
        if (strcmp(log_levels[i].str, arg) == 0)
            return log_levels[i].level;

    error("invalid log level %s", arg);
    return UACPI_LOG_INFO;
}

static arg_spec_t DSDT_PATH_ARG = ARG_POS(
    "dsdt-path-or-keyword",
    "path to the DSDT to run or \"resource-tests\" to run the resource tests"
);

static arg_spec_t EXPECT_ARG = ARG_LIST(
    "expect", 'r',
    "test mode, evaluate \\MAIN and expect <expected-type> <expected-value>"
);
static arg_spec_t EXTRA_TABLES_ARG = ARG_LIST(
    "extra-tables", 'x', "a list of extra SSDTs to load"
);
static arg_spec_t ENUMERATE_NAMESPACE_ARG = ARG_FLAG(
    "enumerate-namespace", 'd', "dump the entire namespace after loading it"
);
static arg_spec_t WHILE_LOOP_TIMEOUT_ARG = ARG_PARAM(
    "while-loop-timeout", 't',
    "number of seconds to use for the while loop timeout"
);
static arg_spec_t LOG_LEVEL_ARG = ARG_PARAM(
    "log-level", 'l',
    "log level to set, one of: debug, trace, info, warning, error"
);
static arg_spec_t HELP_ARG = ARG_HELP(
    "help", 'h', "Display this menu and exit"
);

static arg_spec_t *const POSITIONAL_ARGS[] = {
    &DSDT_PATH_ARG,
};

static arg_spec_t *const OPTION_ARGS[] = {
    &EXPECT_ARG,
    &EXTRA_TABLES_ARG,
    &ENUMERATE_NAMESPACE_ARG,
    &WHILE_LOOP_TIMEOUT_ARG,
    &LOG_LEVEL_ARG,
    &HELP_ARG,
};

static const arg_parser_t PARSER = {
    .positional_args = POSITIONAL_ARGS,
    .num_positional_args = UACPI_ARRAY_SIZE(POSITIONAL_ARGS),
    .option_args = OPTION_ARGS,
    .num_option_args = UACPI_ARRAY_SIZE(OPTION_ARGS),
};

int main(int argc, char *argv[])
{
    const char *dsdt_path_or_keyword;
    const char *expected_value = NULL;
    uacpi_object_type expected_type = UACPI_OBJECT_UNINITIALIZED;
    bool dump_namespace;
    uacpi_log_level log_level;

    parse_args(&PARSER, argc, argv);

    uacpi_context_set_loop_timeout(get_uint_or(&WHILE_LOOP_TIMEOUT_ARG, 3));

    dsdt_path_or_keyword = get(&DSDT_PATH_ARG);
    if (strcmp(dsdt_path_or_keyword, "resource-tests") == 0) {
        run_resource_tests();
        return 0;
    }

    if (is_set(&EXPECT_ARG)) {
        if (EXPECT_ARG.values.count != 2)
            error("bad --expect format");

        expected_type = string_to_object_type(EXPECT_ARG.values.blobs[0].data);
        expected_value = EXPECT_ARG.values.blobs[1].data;
    }

    dump_namespace = is_set(&ENUMERATE_NAMESPACE_ARG);
    // Don't spam the log with traces if enumeration is enabled
    log_level = dump_namespace ? UACPI_LOG_INFO : UACPI_LOG_TRACE;

    if (is_set(&LOG_LEVEL_ARG))
        log_level = log_level_from_string(get(&LOG_LEVEL_ARG));

    uacpi_context_set_log_level(log_level);

    run_test(
        dsdt_path_or_keyword, &EXTRA_TABLES_ARG.values, expected_type,
        expected_value, dump_namespace
    );

    return 0;
}
