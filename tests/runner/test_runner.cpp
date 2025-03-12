#include <iostream>
#include <filesystem>
#include <string>
#include <cstring>
#include <string_view>
#include <cinttypes>
#include <vector>

#include "helpers.h"
#include "argparser.h"
#include <uacpi/context.h>
#include <uacpi/notify.h>
#include <uacpi/utilities.h>
#include <uacpi/resources.h>
#include <uacpi/osi.h>
#include <uacpi/tables.h>
#include <uacpi/opregion.h>
#include <uacpi/event.h>

void run_resource_tests();
void test_object_api();
void test_address_spaces();

static uacpi_object_type string_to_object_type(std::string_view str)
{
    if (str == "int")
        return UACPI_OBJECT_INTEGER;
    if (str == "str")
        return UACPI_OBJECT_STRING;

    throw std::runtime_error(
        std::string("Unsupported type for validation: ") + str.data()
    );
}

static void validate_ret_against_expected(
    uacpi_object& obj, uacpi_object_type expected_type,
    std::string_view expected_val
)
{
    auto ret_is_wrong = [](std::string_view expected, std::string_view actual)
    {
        std::string err;
        err += "returned value '";
        err += actual.data();
        err += "' doesn't match expected '";
        err += expected.data();
        err += "'";

        throw std::runtime_error(err);
    };

    auto type = uacpi_object_get_type(&obj);

    if (type != expected_type) {
        std::string err;
        err += "returned type '";
        err += uacpi_object_type_to_string(type);
        err += "' doesn't match expected '";
        err += uacpi_object_type_to_string(expected_type);
        err += "'";

        throw std::runtime_error(err);
    }

    switch (type) {
    case UACPI_OBJECT_INTEGER: {
        auto expected_int = std::stoull(expected_val.data(), nullptr, 0);
        uacpi_u64 actual_int;

        uacpi_object_get_integer(&obj, &actual_int);

        if (expected_int != actual_int)
            ret_is_wrong(expected_val, std::to_string(actual_int));
    } break;
    case UACPI_OBJECT_STRING: {
        uacpi_data_view view;

        uacpi_object_get_string_or_buffer(&obj, &view);
        auto actual_str = std::string_view(view.text, view.length - 1);

        if (expected_val != actual_str)
            ret_is_wrong(expected_val, actual_str);
    } break;
    default:
        std::abort();
    }
}

static void enumerate_namespace()
{
    auto dump_one_node = [](void*, uacpi_namespace_node *node, uacpi_u32 depth) {
        uacpi_namespace_node_info *info;

        auto nested_printf = [depth](const char *fmt, ...) {
            va_list va;
            size_t padding = depth * 4;

            while (padding-- > 0)
                std::printf(" ");

            va_start(va, fmt);
            std::vprintf(fmt, va);
            va_end(va);
        };

        auto ret = uacpi_get_namespace_node_info(node, &info);
        if (uacpi_unlikely_error(ret)) {
            fprintf(
                stderr, "unable to get node %.4s info: %s\n",
                uacpi_namespace_node_name(node).text,
                uacpi_status_to_string(ret)
            );
            std::exit(1);
        }

        auto *path = uacpi_namespace_node_generate_absolute_path(node);
        nested_printf(
            "%s [%s]", path, uacpi_object_type_to_string(info->type)
        );
        uacpi_free_absolute_path(path);

        if (info->type == UACPI_OBJECT_METHOD)
            std::printf(" (%d args)", info->num_params);

        if (info->flags)
            std::printf(" {\n");

        if (info->flags)
            nested_printf("  _ADR: %016" PRIX64 "\n", info->adr);

        if (info->flags & UACPI_NS_NODE_INFO_HAS_HID)
            nested_printf("  _HID: %s\n", info->hid.value);
        if (info->flags & UACPI_NS_NODE_INFO_HAS_CID) {
            nested_printf("  _CID: ");
            for (size_t i = 0; i < info->cid.num_ids; ++i)
                std::printf("%s ", info->cid.ids[i].value);

            std::printf("\n");
        }
        if (info->flags & UACPI_NS_NODE_INFO_HAS_UID)
            nested_printf("  _UID: %s\n", info->uid.value);
        if (info->flags & UACPI_NS_NODE_INFO_HAS_CLS)
            nested_printf("  _CLS: %s\n", info->cls.value);

        if (info->flags & UACPI_NS_NODE_INFO_HAS_SXD) {
            nested_printf(
                "  _SxD: S1->D%d S2->D%d S3->D%d S4->D%d\n",
                info->sxd[0], info->sxd[1], info->sxd[2], info->sxd[3]
            );
        }
        if (info->flags & UACPI_NS_NODE_INFO_HAS_SXW) {
            nested_printf(
                "  _SxW: S0->D%d S1->D%d S2->D%d S3->D%d S4->D%d\n",
                info->sxw[0], info->sxw[1], info->sxw[2], info->sxw[3],
                info->sxw[4]
            );
        }

        if (info->flags) {
            auto dump_resources = [=](auto cb, const char *name) {
                uacpi_resources *res;

                auto ret = cb(node, &res);
                if (ret == UACPI_STATUS_OK) {
                    // TODO: dump resources here
                    nested_printf("  %s: <%u bytes>\n", name, res->length);
                    uacpi_free_resources(res);
                } else if (ret != UACPI_STATUS_NOT_FOUND) {
                    nested_printf(
                        "  %s: unable to evaluate (%s)\n",
                        name, uacpi_status_to_string(ret)
                    );
                }
            };

            if (info->type == UACPI_OBJECT_DEVICE) {
                dump_resources(uacpi_get_current_resources, "_CRS");
                dump_resources(uacpi_get_possible_resources, "_PRS");
            }

            nested_printf("}\n");
        } else {
            std::printf("\n");
        }

        uacpi_free_namespace_node_info(info);
        return UACPI_ITERATION_DECISION_CONTINUE;
    };

    auto *root = uacpi_namespace_root();

    dump_one_node(nullptr, root, 0);
    uacpi_namespace_for_each_child_simple(root, dump_one_node, nullptr);
}

/*
 * DefinitionBlock ("x.aml", "SSDT", 1, "uTEST", "OVERRIDE", 0xF0F0F0F0)
 * {
 *     Name (VAL, "TestRunner")
 * }
 */
uint8_t table_override[] = {
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
uint8_t runner_id_table[] = {
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
    if (strncmp(hdr->oem_table_id, "DENYTABL", sizeof(hdr->oem_table_id)) == 0)
        return UACPI_TABLE_INSTALLATION_DISPOSITON_DENY;

    if (strncmp(hdr->oem_table_id, "OVERTABL", sizeof(hdr->oem_table_id)) != 0)
        return UACPI_TABLE_INSTALLATION_DISPOSITON_ALLOW;

    *out_override = (uacpi_virt_addr)table_override;
    return UACPI_TABLE_INSTALLATION_DISPOSITON_VIRTUAL_OVERRIDE;
}

static uacpi_status handle_notify(
    uacpi_handle, uacpi_namespace_node *node, uacpi_u64 value
)
{
    auto *path = uacpi_namespace_node_generate_absolute_path(node);
    auto guard = ScopeGuard([path] { std::free((void*)path); });

    std::cout << "Received a notification from " << path << " "
              << std::hex << value << std::endl;

    return UACPI_STATUS_OK;
}

static uacpi_status handle_ec(uacpi_region_op op, uacpi_handle op_data)
{
    switch (op) {
    case UACPI_REGION_OP_READ: {
        auto *rw_data = reinterpret_cast<uacpi_region_rw_data*>(op_data);
        rw_data->value = 0;
        [[fallthrough]];
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
    uacpi_handle, uacpi_namespace_node *, uacpi_u16
)
{
    return UACPI_INTERRUPT_HANDLED | UACPI_GPE_REENABLE;
}

static void run_test(
    std::string_view dsdt_path, const std::vector<std::string>& ssdt_paths,
    uacpi_object_type expected_type, std::string_view expected_value,
    bool dump_namespace
)
{
    acpi_rsdp rsdp {};

    std::vector<path_or_data> ssdts(ssdt_paths.size());
    for (size_t i = 0; i < ssdt_paths.size(); i++)
        ssdts[i] = ssdt_paths[i];

    auto *xsdt = make_xsdt(rsdp, dsdt_path, ssdts);
    auto cleanup = ScopeGuard(
        [&xsdt, &ssdt_paths] {
            uacpi_state_reset();
            delete_xsdt(*xsdt, ssdt_paths.size());
        }
    );

    g_rsdp = reinterpret_cast<uacpi_phys_addr>(&rsdp);

    static uint8_t early_table_buf[4096];
    auto st = uacpi_setup_early_table_access(
        early_table_buf, sizeof(early_table_buf)
    );
    ensure_ok_status(st);

    uacpi_table tbl;
    st = uacpi_table_find_by_signature(ACPI_DSDT_SIGNATURE, &tbl);
    ensure_ok_status(st);

    if (strncmp(tbl.hdr->signature, ACPI_DSDT_SIGNATURE, 4) != 0)
        throw std::runtime_error("broken early table access!");

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
        uacpi_namespace_root(), handle_notify, nullptr
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
        throw std::runtime_error("couldn't uninstall interface");

    st = uacpi_enable_host_interface(UACPI_HOST_INTERFACE_3_0_THERMAL_MODEL);
    ensure_ok_status(st);

    st = uacpi_enable_host_interface(UACPI_HOST_INTERFACE_MODULE_DEVICE);
    ensure_ok_status(st);

    auto is_test_mode = expected_type != UACPI_OBJECT_UNINITIALIZED;
    if (is_test_mode) {
        st = uacpi_table_install(runner_id_table, UACPI_NULL);
        ensure_ok_status(st);
    }

    st = uacpi_namespace_load();
    ensure_ok_status(st);

    if (is_test_mode) {
        uacpi_object *runner_id = UACPI_NULL;
        st = uacpi_eval_typed(UACPI_NULL, "\\_SI.TID", UACPI_NULL,
                              UACPI_OBJECT_STRING_BIT, &runner_id);
        ensure_ok_status(st);

        uacpi_data_view view;
        st = uacpi_object_get_string_or_buffer(runner_id, &view);
        ensure_ok_status(st);

        if (strcmp(view.text, "uACPI") != 0)
            throw std::runtime_error("invalid test runner id");
        uacpi_object_unref(runner_id);
    }

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_EMBEDDED_CONTROLLER,
        handle_ec, nullptr
    );
    ensure_ok_status(st);

    st = uacpi_install_gpe_handler(
        UACPI_NULL, 123, UACPI_GPE_TRIGGERING_EDGE, handle_gpe, UACPI_NULL
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
        // We're done with emulation mode
        return;

    if (expected_value == "check-object-api-works") {
        test_object_api();
        return;
    }

    if (expected_value == "check-address-spaces-work") {
        test_address_spaces();
        return;
    }

    uacpi_object* ret = UACPI_NULL;
    auto guard = ScopeGuard(
        [&ret] { uacpi_object_unref(ret); }
    );

    st = uacpi_eval(UACPI_NULL, "\\MAIN", UACPI_NULL, &ret);

    ensure_ok_status(st);
    if (ret == UACPI_NULL)
        throw std::runtime_error("\\MAIN didn't return a value");
    validate_ret_against_expected(*ret, expected_type, expected_value);
}

static uacpi_log_level log_level_from_string(std::string_view arg)
{
    static std::pair<std::string_view, uacpi_log_level> log_levels[] = {
        { "debug", UACPI_LOG_DEBUG },
        { "trace", UACPI_LOG_TRACE },
        { "info", UACPI_LOG_INFO },
        { "warning", UACPI_LOG_WARN },
        { "error", UACPI_LOG_ERROR },
    };

    for (auto& lvl : log_levels) {
        if (lvl.first == arg)
            return lvl.second;
    }

    throw std::runtime_error(std::string("invalid log level ") + arg.data());
}

int main(int argc, char** argv)
{
    auto args = ArgParser {};
    args.add_positional(
            "dsdt-path-or-keyword",
            "path to the DSDT to run or \"resource-tests\" to run the resource "
            "tests and exit"
        )
        .add_list(
            "expect", 'r', "test mode, evaluate \\MAIN and expect "
            "<expected_type> <expected_value>"
        )
        .add_list(
            "extra-tables", 'x', "a list of extra SSDTs to load"
        )
        .add_flag(
            "enumerate-namespace", 'd',
            "dump the entire namespace after loading it"
        )
        .add_param(
            "while-loop-timeout", 't',
            "number of seconds to use for the while loop timeout"
        )
        .add_param(
            "log-level", 'l',
            "log level to set, one of: debug, trace, info, warning, error"
        )
        .add_help(
            "help", 'h', "Display this menu and exit",
            [&]() { std::cout << "uACPI test runner:\n" << args; }
        );

    try {
        args.parse(argc, argv);

        uacpi_context_set_loop_timeout(
            args.get_uint_or("while-loop-timeout", 3)
        );

        auto dsdt_path_or_keyword = args.get("dsdt-path-or-keyword");
        if (dsdt_path_or_keyword == "resource-tests") {
            run_resource_tests();
            return 0;
        }

        std::string_view expected_value;
        uacpi_object_type expected_type = UACPI_OBJECT_UNINITIALIZED;

        if (args.is_set('r')) {
            auto& expect = args.get_list('r');
            if (expect.size() != 2)
                throw std::runtime_error("bad --expect format");

            expected_type = string_to_object_type(expect[0]);
            expected_value = expect[1];
        }

        auto dump_namespace = args.is_set('d');
        // Don't spam the log with traces if enumeration is enabled
        auto log_level = dump_namespace ? UACPI_LOG_INFO : UACPI_LOG_TRACE;

        if (args.is_set('l'))
            log_level = log_level_from_string(args.get('l'));

        uacpi_context_set_log_level(log_level);

        run_test(dsdt_path_or_keyword, args.get_list_or("extra-tables", {}),
                 expected_type, expected_value, dump_namespace);
    } catch (const std::exception& ex) {
        std::cerr << "unexpected error: " << ex.what() << std::endl;
        return 1;
    }
}
