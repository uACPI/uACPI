#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <filesystem>
#include <fstream>

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

void build_xsdt_from_file(full_xsdt& xsdt, acpi_rsdp& rsdp,
                          std::string_view path)
{
    auto& fadt = *new acpi_fadt {};
    fadt.hdr.length = sizeof(fadt);
    fadt.hdr.revision = 6;

    auto* dsdt = reinterpret_cast<acpi_dsdt*>(read_entire_file(path));
    // Always force the signature to DSDT as that's what we're building
    memcpy(dsdt->hdr.signature, ACPI_DSDT_SIGNATURE,
           sizeof(ACPI_DSDT_SIGNATURE) - 1);

    fadt.x_dsdt = reinterpret_cast<uacpi_phys_addr>(dsdt);
    memcpy(fadt.hdr.signature, ACPI_FADT_SIGNATURE,
           sizeof(ACPI_FADT_SIGNATURE) - 1);
    fadt.hdr.checksum = gen_checksum(&fadt, sizeof(fadt));

    xsdt.fadt = &fadt;
    xsdt.hdr.length = sizeof(xsdt);
    xsdt.hdr.revision = dsdt->hdr.revision;
    memcpy(xsdt.hdr.oemid, dsdt->hdr.oemid, sizeof(dsdt->hdr.oemid));
    xsdt.hdr.oem_revision = dsdt->hdr.oem_revision;

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
    xsdt.hdr.checksum = gen_checksum(&xsdt, sizeof(xsdt));
}

void* read_entire_file(std::string_view path)
{
    size_t file_size = std::filesystem::file_size(path);
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

    return buf;
}
