#include <string.h>
#include <unordered_map>

#include "helpers.h"
#include "argparser.h"

#include <uacpi/uacpi.h>
#include <uacpi/tables.h>
#include <uacpi/kernel_api.h>
#include <uacpi/acpi.h>

void uacpi_kernel_log(enum uacpi_log_level lvl, const char *text)
{
    std::printf("[%s] %s", uacpi_log_level_to_string(lvl), text);
}

void* uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size)
{
    return reinterpret_cast<void*>(addr);
}

void uacpi_kernel_unmap(void*, uacpi_size) { }

uacpi_phys_addr g_rsdp;

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_addr)
{
    *out_addr = g_rsdp;
    return UACPI_STATUS_OK;
}

static uint8_t test_dsdt[] = {
    0x53, 0x53, 0x44, 0x54, 0x35, 0x00, 0x00, 0x00,
    0x01, 0xa1, 0x75, 0x54, 0x45, 0x53, 0x54, 0x00,
    0x4f, 0x56, 0x45, 0x52, 0x52, 0x49, 0x44, 0x45,
    0xf0, 0xf0, 0xf0, 0xf0, 0x49, 0x4e, 0x54, 0x4c,
    0x25, 0x09, 0x20, 0x20, 0x08, 0x56, 0x41, 0x4c,
    0x5f, 0x0d, 0x54, 0x65, 0x73, 0x74, 0x52, 0x75,
    0x6e, 0x6e, 0x65, 0x72, 0x00
};

static uint8_t test_mcfg[] = {
    0x4d, 0x43, 0x46, 0x47, 0x3c, 0x00, 0x00, 0x00,
    0x01, 0x39, 0x48, 0x50, 0x51, 0x4f, 0x45, 0x4d,
    0x38, 0x35, 0x34, 0x39, 0x20, 0x20, 0x20, 0x20,
    0x01, 0x00, 0x00, 0x00, 0x48, 0x50, 0x20, 0x20,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f,
    0x00, 0x00, 0x00, 0x00
};

static void ensure_signature_is(const char *signature, uacpi_table tbl)
{
    if (strncmp(tbl.hdr->signature, signature, 4) == 0)
        return;

    char actual_signature[5]{ };
    std::memcpy(
        actual_signature, tbl.hdr->signature,
        sizeof(uacpi_object_name)
    );

    throw std::runtime_error(
        std::string("incorrect table signature: ") +
        "expected " + signature + " got " + actual_signature
    );
}

static void find_one_table(const char *signature)
{
    uacpi_table tbl;
    uacpi_status st;

    st = uacpi_table_find_by_signature(signature, &tbl);
    ensure_ok_status(st);

    ensure_signature_is(signature, tbl);

    std::printf("%4.4s OK\n", signature);
    uacpi_table_unref(&tbl);
};

static void test_basic_operation()
{
    find_one_table(ACPI_FADT_SIGNATURE);
    find_one_table(ACPI_DSDT_SIGNATURE);
}

static void test_table_installation()
{
    uacpi_status st;
    uacpi_table tbl;

    st = uacpi_table_install(test_mcfg, &tbl);
    ensure_ok_status(st);
    ensure_signature_is(ACPI_MCFG_SIGNATURE, tbl);
    uacpi_table_unref(&tbl);

    find_one_table(ACPI_MCFG_SIGNATURE);

    st = uacpi_table_install_physical(
        (uacpi_phys_addr)((uintptr_t)test_mcfg), &tbl
    );
    ensure_ok_status(st);
    ensure_signature_is(ACPI_MCFG_SIGNATURE, tbl);
    uacpi_table_unref(&tbl);
}

static std::unordered_map<std::string, void(*)()> test_cases = {
    { "basic-operation", test_basic_operation },
    { "table-installation", test_table_installation },
};

int main(int argc, char** argv)
{
    auto args = ArgParser{};
    args.add_positional(
        "test-case", "name of the test case"
    )
    .add_help(
        "help", 'h', "Display this menu and exit",
        [&]() { std::cout << "uACPI test runner:\n" << args; }
    );

    try {
        args.parse(argc, argv);

        acpi_rsdp rsdp{};

        auto *xsdt = make_xsdt(rsdp, std::span(test_dsdt), {});
        auto cleanup = ScopeGuard(
            [&xsdt] {
                uacpi_state_reset();
                delete_xsdt(*xsdt, 0);
            }
        );

        g_rsdp = reinterpret_cast<uacpi_phys_addr>(&rsdp);

        static uint8_t early_table_buf[4096];
        auto st = uacpi_setup_early_table_access(
            early_table_buf, sizeof(early_table_buf)
        );
        ensure_ok_status(st);

        test_cases[args.get("test-case")]();
    } catch (std::exception& ex) {
        std::cerr << "Test error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
