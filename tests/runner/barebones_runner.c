#include "argparser.h"
#include "helpers.h"
#include <stdio.h>
#include <string.h>
#include <uacpi/acpi.h>
#include <uacpi/kernel_api.h>
#include <uacpi/tables.h>
#include <uacpi/uacpi.h>

void uacpi_kernel_log(enum uacpi_log_level lvl, const char *text)
{
    printf("[%s] %s", uacpi_log_level_to_string(lvl), text);
}

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len)
{
    UACPI_UNUSED(len);

    return (void*)((uintptr_t)addr);
}

void uacpi_kernel_unmap(void *ptr, uacpi_size len)
{
    UACPI_UNUSED(ptr);
    UACPI_UNUSED(len);
}

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

/*
 * 4 Local APICs [0, 1, 2, 3]
 * 2 IOAPICs [4, 5]
 * 2 ISOs [0->2, 9->9]
 * 4 NMIs [0, 1, 2, 3]
 */
static uint8_t test_apic[] = {
    0x41, 0x50, 0x49, 0x43, 0x90, 0x00, 0x00, 0x00,
    0x03, 0x1a, 0x48, 0x50, 0x51, 0x4f, 0x45, 0x4d,
    0x53, 0x4c, 0x49, 0x43, 0x2d, 0x4d, 0x50, 0x43,
    0x01, 0x00, 0x00, 0x00, 0x48, 0x50, 0x20, 0x20,
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xe0, 0xfe,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x02, 0x02,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x03, 0x03,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x04, 0x00,
    0x00, 0x00, 0xc0, 0xfe, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x0c, 0x05, 0x00, 0x00, 0x10, 0xc0, 0xfe,
    0x18, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a,
    0x00, 0x09, 0x09, 0x00, 0x00, 0x00, 0x0f, 0x00,
    0x04, 0x06, 0x00, 0x05, 0x00, 0x01, 0x04, 0x06,
    0x01, 0x05, 0x00, 0x01, 0x04, 0x06, 0x02, 0x05,
    0x00, 0x01, 0x04, 0x06, 0x03, 0x05, 0x00, 0x01
};

static void ensure_signature_is(const char *signature, uacpi_table tbl)
{
    if (strncmp(tbl.hdr->signature, signature, 4) == 0)
        return;

    error(
        "incorrect table signature: expected %s got %.4s\n", signature,
        tbl.hdr->signature
    );
}

static void find_one_table(const char *signature)
{
    uacpi_table tbl;
    uacpi_status st;

    st = uacpi_table_find_by_signature(signature, &tbl);
    ensure_ok_status(st);

    ensure_signature_is(signature, tbl);

    printf("%4.4s OK\n", signature);
    uacpi_table_unref(&tbl);
}

static void test_basic_operation(void)
{
    find_one_table(ACPI_FADT_SIGNATURE);
    find_one_table(ACPI_DSDT_SIGNATURE);
}

static void test_table_installation(void)
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

static uacpi_iteration_decision check_madt(
    uacpi_handle user, struct acpi_entry_hdr *hdr
)
{
    size_t *idx = user;
    struct acpi_madt_lapic *lapic;
    struct acpi_madt_ioapic *ioapic;
    struct acpi_madt_interrupt_source_override *iso;
    struct acpi_madt_lapic_nmi *nmi;

    switch (*idx) {
    case 0:
    case 1:
    case 2:
    case 3:
        if (hdr->type != ACPI_MADT_ENTRY_TYPE_LAPIC)
            goto out_unexpected;
        lapic = (struct acpi_madt_lapic*)hdr;
        if (lapic->id != *idx)
            error("unexpected LAPIC id %d (idx %d)\n", lapic->id, *idx);
        break;
    case 4:
    case 5:
        if (hdr->type != ACPI_MADT_ENTRY_TYPE_IOAPIC)
            goto out_unexpected;
        ioapic = (struct acpi_madt_ioapic*)hdr;
        if (ioapic->id != *idx)
            error("unexpected IOAPIC id %d (idx %d)\n", ioapic->id, *idx);
        break;
    case 6:
    case 7:
        if (hdr->type != ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE)
            goto out_unexpected;
        iso = (struct acpi_madt_interrupt_source_override*)hdr;
        if ((*idx == 6 && iso->source != 0) ||
            (*idx == 7 && iso->source != 9))
            error("unexpected ISO source %d (idx %d)\n", iso->source, *idx);
        break;
    case 8:
    case 9:
    case 10:
    case 11:
        if (hdr->type != ACPI_MADT_ENTRY_TYPE_LAPIC_NMI)
            goto out_unexpected;
        nmi = (struct acpi_madt_lapic_nmi*)hdr;
        if (nmi->uid != (*idx - 8))
            error("unexpected LAPIC NMI uid %d (idx %d)\n", nmi->uid, *idx);
        break;
    default:
        goto out_unexpected;
    }

    (*idx)++;
    return UACPI_ITERATION_DECISION_CONTINUE;

out_unexpected:
    error("unexpected MADT entry type %d (idx = %zu)\n", hdr->type, *idx);
    return UACPI_ITERATION_DECISION_BREAK;
}

#define CHECK_SUBTEST_FAILED                                         \
    if (st != UACPI_STATUS_INVALID_TABLE_LENGTH)                     \
        error("unexpected status %s\n", uacpi_status_to_string(st));

#define CHECK_SUBTEST_SUCCEEDED                            \
    if (idx != 12)                                         \
        error("invalid number of iterations: %zu\n", idx);

#define FOREACH_SUBTEST(check_cond)                         \
    idx = 0;                                                \
    st = uacpi_for_each_subtable(                           \
        tbl.hdr, sizeof(struct acpi_madt), check_madt, &idx \
    );                                                      \
    check_cond;                                             \

static void test_foreach_subtable(void)
{
    uacpi_status st;
    uacpi_table tbl;
    size_t idx = 0;

    st = uacpi_table_install(test_apic, &tbl);
    ensure_ok_status(st);
    ensure_signature_is(ACPI_MADT_SIGNATURE, tbl);
    uacpi_table_unref(&tbl);

    FOREACH_SUBTEST(CHECK_SUBTEST_SUCCEEDED);

    // Make the size slightly larger, make sure we don't crash
    test_apic[4] += 1;
    FOREACH_SUBTEST(CHECK_SUBTEST_SUCCEEDED);

    // Change the size to 1 byte and make sure we don't crash
    test_apic[4] = 1;
    FOREACH_SUBTEST(CHECK_SUBTEST_FAILED);

    // Cutoff subtable
    test_apic[4] = sizeof(struct acpi_madt) + sizeof(struct acpi_entry_hdr) + 1;
    FOREACH_SUBTEST(CHECK_SUBTEST_FAILED);

    test_apic[4] = sizeof(test_apic);
    // Out-of-bounds subtable
    test_apic[sizeof(test_apic) - 5]++;
    FOREACH_SUBTEST(CHECK_SUBTEST_FAILED);

    // all pass
    test_apic[sizeof(test_apic) - 5]--;
    uacpi_table_unref(&tbl);
}

static struct {
    const char *name;
    void (*func)(void);
} test_cases[] = {
    { "basic-operation", test_basic_operation },
    { "table-installation", test_table_installation },
    { "foreach-subtable", test_foreach_subtable },
};

static arg_spec_t TEST_CASE_ARG = ARG_POS("test-case", "name of the test case");

static arg_spec_t HELP_ARG = ARG_HELP(
    "help", 'h', "Display this menu and exit"
);

static arg_spec_t *const POSITIONAL_ARGS[] = {
    &TEST_CASE_ARG,
};

static arg_spec_t *const OPTION_ARGS[] = {
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
    static uint8_t early_table_buf[4096];
    struct acpi_rsdp rsdp = { 0 };
    struct full_xsdt *xsdt;
    uacpi_status st;
    const char *test_case;
    size_t i;

    parse_args(&PARSER, argc, argv);

    xsdt = make_xsdt_blob(&rsdp, test_dsdt, sizeof(test_dsdt));

    g_rsdp = (uacpi_phys_addr)((uintptr_t)&rsdp);

    st = uacpi_setup_early_table_access(
        early_table_buf, sizeof(early_table_buf)
    );
    ensure_ok_status(st);

    test_case = get(&TEST_CASE_ARG);

    for (i = 0; i < UACPI_ARRAY_SIZE(test_cases); i++) {
        if (strcmp(test_case, test_cases[i].name) == 0) {
            test_cases[i].func();
            uacpi_state_reset();
            delete_xsdt(xsdt, 0);
            return 0;
        }
    }

    error("unknown test case '%s'", test_case);
    return 1;
}
