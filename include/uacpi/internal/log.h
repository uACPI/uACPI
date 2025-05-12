#pragma once

#include <uacpi/kernel_api.h>
#include <uacpi/internal/context.h>
#include <uacpi/log.h>

#ifdef __WATCOMC__
#define uacpi_debug(...)
#define uacpi_trace(...)
#define uacpi_info(...)
#define uacpi_warn(...)
#define uacpi_error(...)
#define uacpi_log_lvl(lvl, ...)
#else

#ifdef UACPI_FORMATTED_LOGGING
#define uacpi_log uacpi_kernel_log
#else
UACPI_PRINTF_DECL(2, 3)
void uacpi_log(uacpi_log_level, const uacpi_char*, ...);
#endif

#define uacpi_log_lvl(lvl, ...) \
    do { if (uacpi_should_log(lvl)) uacpi_log(lvl, __VA_ARGS__); } while (0)

#define uacpi_debug(...) uacpi_log_lvl(UACPI_LOG_DEBUG, __VA_ARGS__)
#define uacpi_trace(...) uacpi_log_lvl(UACPI_LOG_TRACE, __VA_ARGS__)
#define uacpi_info(...)  uacpi_log_lvl(UACPI_LOG_INFO, __VA_ARGS__)
#define uacpi_warn(...)  uacpi_log_lvl(UACPI_LOG_WARN, __VA_ARGS__)
#define uacpi_error(...) uacpi_log_lvl(UACPI_LOG_ERROR, __VA_ARGS__)

#endif

void uacpi_logger_initialize(void);
