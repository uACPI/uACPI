#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <filesystem>
#include <fstream>
#include <string>

#include "helpers.h"

static uacpi_u8 gen_checksum(void *table, uacpi_size size)
{
    uacpi_u8 *bytes = reinterpret_cast<uacpi_u8*>(table);
    uacpi_u8 csum = 0;
    uacpi_size i;

    for (i = 0; i < size; ++i)
        csum += bytes[i];

    return 256 - csum;
}

void set_oem(char(&oemid)[6])
{
    memcpy(oemid, "uOEMID", sizeof(oemid));
}

void set_oem_table_id(char(&oemid_table_id)[8])
{
    memcpy(oemid_table_id, "uTESTTBL", sizeof(oemid_table_id));
}


using table_item = std::pair<void*, size_t>;

static void get_table(table_item& item, const path_or_data& src)
{
    if (std::holds_alternative<std::string_view>(src)) {
       item = read_entire_file(
            std::get<std::string_view>(src), sizeof(acpi_sdt_hdr)
       );
       return;
    }

    auto table_data = std::get<1>(src);
    auto* heap_table_data = new uint8_t[table_data.size()];

    std::memcpy(heap_table_data, table_data.data(), table_data.size());
    item = std::make_pair(heap_table_data, table_data.size());
}

full_xsdt* make_xsdt(
    acpi_rsdp& rsdp, path_or_data dsdt_item,
    const std::vector<path_or_data>& ssdts
)
{
    memcpy(&rsdp.signature, ACPI_RSDP_SIGNATURE, sizeof(ACPI_RSDP_SIGNATURE) - 1);
    set_oem(rsdp.oemid);

    auto xsdt_bytes = sizeof(full_xsdt);
    xsdt_bytes += ssdts.size() * sizeof(acpi_sdt_hdr*);

    auto& xsdt = *new (std::calloc(xsdt_bytes, 1)) full_xsdt();
    std::vector<table_item> tables(ssdts.size() + 1);

    auto cleanup = ScopeGuard(
        [&tables, &xsdt] {
            for (auto& table : tables)
                delete[] reinterpret_cast<uint8_t*>(table.first);

            xsdt.~full_xsdt();
            std::free(&xsdt);
        }
    );

    set_oem(xsdt.hdr.oemid);
    set_oem_table_id(xsdt.hdr.oem_table_id);

    get_table(tables[0], dsdt_item);

    for (size_t i = 0; i < ssdts.size(); ++i)
        get_table(tables[1 + i], ssdts[i]);

    for (size_t i = 0; i < tables.size(); ++i) {
        auto& table = tables[i];
        auto *hdr = reinterpret_cast<acpi_sdt_hdr*>(table.first);

        if (hdr->length > table.second)
            throw std::runtime_error("invalid table " + std::to_string(i) + " size");

        auto *signature = ACPI_DSDT_SIGNATURE;
        if (i > 0) {
            signature = ACPI_SSDT_SIGNATURE;
            xsdt.ssdts[i - 1] = hdr;

            /*
             * Make the pointer NULL here since this table is now managed by the
             * XSDT, and it's the caller's responsibility to clean it up.
             */
            table.first = nullptr;
        }

        memcpy(hdr, signature, sizeof(uacpi_object_name));

        hdr->checksum = 0;
        hdr->checksum = gen_checksum(hdr, hdr->length);
    }

    cleanup.disarm();

    auto& fadt = *new acpi_fadt {};
    set_oem(fadt.hdr.oemid);
    set_oem_table_id(fadt.hdr.oem_table_id);

    fadt.hdr.length = sizeof(fadt);
    fadt.hdr.revision = 6;

    fadt.pm1a_cnt_blk = 0xFFEE;
    fadt.pm1_cnt_len = 2;

    fadt.pm1a_evt_blk = 0xDEAD;
    fadt.pm1_evt_len = 4;

    fadt.pm2_cnt_blk = 0xCCDD;
    fadt.pm2_cnt_len = 1;

    fadt.gpe0_blk_len = 0x20;
    fadt.gpe0_blk = 0xDEAD;

    fadt.gpe1_base = 128;
    fadt.gpe1_blk = 0xBEEF;
    fadt.gpe1_blk_len = 0x20;

    fadt.x_dsdt = reinterpret_cast<uacpi_phys_addr>(tables[0].first);
    memcpy(fadt.hdr.signature, ACPI_FADT_SIGNATURE,
           sizeof(ACPI_FADT_SIGNATURE) - 1);

    auto *facs = new acpi_facs { };
    facs->length = sizeof(*facs);
    memcpy(facs->signature, ACPI_FACS_SIGNATURE,
           sizeof(ACPI_FACS_SIGNATURE) - 1);

    fadt.x_firmware_ctrl = reinterpret_cast<uintptr_t>(facs);

    fadt.hdr.checksum = gen_checksum(&fadt, sizeof(fadt));

    xsdt.fadt = &fadt;
    xsdt.hdr.length = sizeof(xsdt) + sizeof(acpi_sdt_hdr*) * ssdts.size();

    auto& dsdt = *reinterpret_cast<acpi_sdt_hdr*>(tables[0].first);
    xsdt.hdr.revision = dsdt.revision;
    memcpy(xsdt.hdr.oemid, dsdt.oemid, sizeof(dsdt.oemid));
    xsdt.hdr.oem_revision = dsdt.oem_revision;

    if constexpr (sizeof(void*) == 4) {
        memcpy(xsdt.hdr.signature, ACPI_RSDT_SIGNATURE,
               sizeof(ACPI_XSDT_SIGNATURE) - 1);

        rsdp.rsdt_addr = reinterpret_cast<size_t>(&xsdt);
        rsdp.revision = 1;
        rsdp.checksum = gen_checksum(
            &rsdp, offsetof(acpi_rsdp, length)
        );
    } else {
        memcpy(xsdt.hdr.signature, ACPI_XSDT_SIGNATURE,
               sizeof(ACPI_XSDT_SIGNATURE) - 1);

        rsdp.xsdt_addr = reinterpret_cast<size_t>(&xsdt);
        rsdp.length = sizeof(rsdp);
        rsdp.revision = 2;
        rsdp.checksum = gen_checksum(
            &rsdp, offsetof(acpi_rsdp, length)
        );
        rsdp.extended_checksum = gen_checksum(&rsdp, sizeof(rsdp));
    }
    xsdt.hdr.checksum = gen_checksum(&xsdt, xsdt.hdr.length);

    return &xsdt;
}

void delete_xsdt(full_xsdt& xsdt, size_t num_tables)
{
    if (xsdt.fadt) {
        delete[] reinterpret_cast<uint8_t*>(
            static_cast<uintptr_t>(xsdt.fadt->x_dsdt)
        );
        delete reinterpret_cast<acpi_facs*>(
            static_cast<uintptr_t>(xsdt.fadt->x_firmware_ctrl)
        );
        delete xsdt.fadt;
    }

    for (size_t i = 0; i < num_tables; ++i)
        delete[] xsdt.ssdts[i];

    xsdt.~full_xsdt();
    std::free(&xsdt);
}

std::pair<void*, size_t>
read_entire_file(std::string_view path, size_t min_size)
{
    size_t file_size = std::filesystem::file_size(path);
    if (file_size < min_size) {
        throw std::runtime_error(
            std::string("file ") + path.data() + " is too small"
        );
    }

    std::ifstream file(path.data(), std::ios::binary);

    if (!file)
        throw std::runtime_error(
            std::string("failed to open file ") + path.data()
        );

    auto* buf = new uint8_t[file_size];
    file.read(reinterpret_cast<char*>(buf), file_size);

    if (!file) {
        delete[] buf;
        throw std::runtime_error(
            std::string("failed to read entire file ") + path.data()
        );
    }

    return { buf, file_size };
}
