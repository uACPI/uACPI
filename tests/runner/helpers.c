#include "helpers.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uacpi/acpi.h>

static uacpi_u8 gen_checksum(void *table, uacpi_size size)
{
    uacpi_u8 *bytes = table;
    uacpi_u8 csum = 0;
    uacpi_size i;

    for (i = 0; i < size; ++i)
        csum += bytes[i];

    return 256 - csum;
}

void set_oem(char (*oemid)[6])
{
    memcpy(oemid, "uOEMID", sizeof(*oemid));
}

void set_oem_table_id(char (*oemid_table_id)[8])
{
    memcpy(oemid_table_id, "uTESTTBL", sizeof(*oemid_table_id));
}

static void get_table_path(blob_t *item, const char *path)
{
    *item = read_entire_file(path, sizeof(struct acpi_sdt_hdr));
}

static void get_table_blob(blob_t *item, const void *data, size_t size)
{
    item->data = do_malloc(size);
    item->size = size;
    memcpy(item->data, data, size);
}

static struct full_xsdt *do_make_xsdt(
    struct acpi_rsdp *rsdp, const blob_t *tables, size_t num_tables
)
{
    size_t xsdt_bytes = sizeof(struct full_xsdt);
    struct full_xsdt *xsdt;
    size_t i;
    struct acpi_fadt *fadt;
    struct acpi_facs *facs;
    struct acpi_sdt_hdr *dsdt;

    memcpy(
        &rsdp->signature, ACPI_RSDP_SIGNATURE,
        sizeof(ACPI_RSDP_SIGNATURE) - 1
    );
    set_oem(&rsdp->oemid);

    xsdt_bytes += (num_tables - 1) * sizeof(struct acpi_sdt_hdr*);

    xsdt = do_calloc(xsdt_bytes, 1);

    set_oem(&xsdt->hdr.oemid);
    set_oem_table_id(&xsdt->hdr.oem_table_id);

    for (i = 0; i < num_tables; ++i) {
        struct acpi_sdt_hdr *hdr = tables[i].data;
        char *signature = ACPI_DSDT_SIGNATURE;

        if (hdr->length > tables[i].size)
            error("invalid table %zu size", i);

        if (i > 0) {
            signature = ACPI_SSDT_SIGNATURE;
            xsdt->ssdts[i - 1] = hdr;
        }

        memcpy(hdr, signature, sizeof(uacpi_object_name));

        hdr->checksum = 0;
        hdr->checksum = gen_checksum(hdr, hdr->length);
    }

    fadt = do_calloc(1, sizeof(*fadt));
    set_oem(&fadt->hdr.oemid);
    set_oem_table_id(&fadt->hdr.oem_table_id);

    fadt->hdr.length = sizeof(*fadt);
    fadt->hdr.revision = 6;

    fadt->pm1a_cnt_blk = 0xFFEE;
    fadt->pm1_cnt_len = 2;

    fadt->pm1a_evt_blk = 0xDEAD;
    fadt->pm1_evt_len = 4;

    fadt->pm2_cnt_blk = 0xCCDD;
    fadt->pm2_cnt_len = 1;

    fadt->gpe0_blk_len = 0x20;
    fadt->gpe0_blk = 0xDEAD;

    fadt->gpe1_base = 128;
    fadt->gpe1_blk = 0xBEEF;
    fadt->gpe1_blk_len = 0x20;

    fadt->x_dsdt = (uacpi_phys_addr)((uintptr_t)tables[0].data);
    memcpy(
        fadt->hdr.signature, ACPI_FADT_SIGNATURE,
        sizeof(ACPI_FADT_SIGNATURE) - 1
    );

    facs = do_calloc(1, sizeof(*facs));
    facs->length = sizeof(*facs);
    memcpy(
        facs->signature, ACPI_FACS_SIGNATURE,
        sizeof(ACPI_FACS_SIGNATURE) - 1
    );

    fadt->x_firmware_ctrl = (uintptr_t)facs;

    fadt->hdr.checksum = gen_checksum(fadt, sizeof(*fadt));

    xsdt->fadt = fadt;
    xsdt->hdr.length = sizeof(*xsdt) +
                       sizeof(struct acpi_sdt_hdr*) * (num_tables - 1);

    dsdt = tables[0].data;
    xsdt->hdr.revision = dsdt->revision;
    memcpy(xsdt->hdr.oemid, dsdt->oemid, sizeof(dsdt->oemid));
    xsdt->hdr.oem_revision = dsdt->oem_revision;

    if (sizeof(void*) == 4) {
        memcpy(
            xsdt->hdr.signature, ACPI_RSDT_SIGNATURE,
            sizeof(ACPI_XSDT_SIGNATURE) - 1
        );

        rsdp->rsdt_addr = (size_t)xsdt;
        rsdp->revision = 1;
        rsdp->checksum = gen_checksum(rsdp, offsetof(struct acpi_rsdp, length));
    } else {
        memcpy(
            xsdt->hdr.signature, ACPI_XSDT_SIGNATURE,
            sizeof(ACPI_XSDT_SIGNATURE) - 1
        );

        rsdp->xsdt_addr = (size_t)xsdt;
        rsdp->length = sizeof(*rsdp);
        rsdp->revision = 2;
        rsdp->checksum = gen_checksum(rsdp, offsetof(struct acpi_rsdp, length));
        rsdp->extended_checksum = gen_checksum(rsdp, sizeof(*rsdp));
    }
    xsdt->hdr.checksum = gen_checksum(xsdt, xsdt->hdr.length);

    return xsdt;
}

struct full_xsdt *make_xsdt(
    struct acpi_rsdp *rsdp, const char *dsdt_path, const vector_t *ssdts
)
{
    vector_t tables;
    size_t i;
    struct full_xsdt *xsdt;

    vector_init(&tables, ssdts->count + 1);

    get_table_path(&tables.blobs[0], dsdt_path);

    for (i = 0; i < ssdts->count; ++i)
        get_table_path(&tables.blobs[1 + i], ssdts->blobs[i].data);

    xsdt = do_make_xsdt(rsdp, tables.blobs, tables.count);
    vector_cleanup(&tables);
    return xsdt;
}

struct full_xsdt *make_xsdt_blob(
    struct acpi_rsdp *rsdp, const void *dsdt, size_t dsdt_size
)
{
    blob_t blob;

    get_table_blob(&blob, dsdt, dsdt_size);
    return do_make_xsdt(rsdp, &blob, 1);
}

void delete_xsdt(struct full_xsdt *xsdt, size_t num_tables)
{
    size_t i;

    if (xsdt->fadt) {
        free((void*)((uintptr_t)xsdt->fadt->x_dsdt));
        free((struct acpi_facs*)((uintptr_t)xsdt->fadt->x_firmware_ctrl));
        free(xsdt->fadt);
    }

    for (i = 0; i < num_tables; i++)
        free(xsdt->ssdts[i]);

    free(xsdt);
}

blob_t read_entire_file(const char *path, size_t min_size)
{
    FILE *file = fopen(path, "rb");
    long size;
    void *buf;
    blob_t blob = { 0 };

    if (!file)
        error("failed to open file %s", path);

    if (fseek(file, 0, SEEK_END))
        error("failed to seek file %s", path);

    size = ftell(file);
    if (size < 0)
        error("failed to get size of file %s", path);
    if (size < (long)min_size)
        error("file %s is too small", path);
    if (fseek(file, 0, SEEK_SET))
        error("failed to seek file %s", path);

    buf = do_malloc(size);

    if (fread(buf, size, 1, file) != 1)
        error("failed to read from %s", path);

    if (fclose(file))
        error("failed to close file %s", path);

    blob.data = buf;
    blob.size = size;
    return blob;
}
