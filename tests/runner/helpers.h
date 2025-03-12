#include <string_view>
#include <vector>
#include <stdexcept>
#include <variant>
#include <span>

#include <uacpi/acpi.h>
#include <uacpi/uacpi.h>

template <typename ExprT>
class ScopeGuard
{
public:
    ScopeGuard(ExprT expr)
            : callback(std::move(expr)) {}

    ~ScopeGuard() { if (!disarmed) callback(); }

    void disarm() { disarmed = true; }

private:
    ExprT callback;
    bool disarmed { false };
};

extern bool g_expect_virtual_addresses;
extern uacpi_phys_addr g_rsdp;

UACPI_PACKED(struct full_xsdt {
    struct acpi_sdt_hdr hdr;
    acpi_fadt* fadt;
    struct acpi_sdt_hdr* ssdts[];
})

void set_oem(char (&oemid)[6]);
void set_oem_table_id(char(&oemid_table_id)[8]);

using path_or_data = std::variant<std::string_view, std::span<uint8_t>>;

full_xsdt* make_xsdt(acpi_rsdp& rsdp, path_or_data dsdt_path,
                     const std::vector<path_or_data>& ssdt_paths);
void delete_xsdt(full_xsdt& xsdt, size_t num_tables);

std::pair<void*, size_t>
read_entire_file(std::string_view path, size_t min_size = 0);

inline void ensure_ok_status(uacpi_status st)
{
    if (st == UACPI_STATUS_OK)
        return;

    auto msg = uacpi_status_to_string(st);
    throw std::runtime_error(std::string("uACPI error: ") + msg);
}

static inline const char* uacpi_log_level_to_string(uacpi_log_level lvl)
{
    switch (lvl) {
    case UACPI_LOG_DEBUG:
        return "DEBUG";
    case UACPI_LOG_TRACE:
        return "TRACE";
    case UACPI_LOG_INFO:
        return "INFO";
    case UACPI_LOG_WARN:
        return "WARN";
    case UACPI_LOG_ERROR:
        return "ERROR";
    default:
        std::abort();
    }
}
