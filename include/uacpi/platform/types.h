#pragma once

/*
 * Platform-specific types go here. This is the default placeholder using
 * types from the standard headers.
 */

#ifdef UACPI_OVERRIDE_TYPES
#include "uacpi_types.h"
#else

#ifdef __WATCOMC__

#define uintptr_t unsigned int *
#ifndef NULL
#define NULL 0
#endif
#define false 0
#define true 1

typedef int bool;
typedef int size_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef signed long long int64_t;

#else

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#endif

#include <stdarg.h>

#include <uacpi/helpers.h>

typedef uint8_t uacpi_u8;
typedef uint16_t uacpi_u16;
typedef uint32_t uacpi_u32;
typedef uint64_t uacpi_u64;

typedef int8_t uacpi_i8;
typedef int16_t uacpi_i16;
typedef int32_t uacpi_i32;
typedef int64_t uacpi_i64;

#define UACPI_TRUE true
#define UACPI_FALSE false
typedef bool uacpi_bool;

#define UACPI_NULL NULL

typedef uintptr_t uacpi_uintptr;
typedef uacpi_uintptr uacpi_virt_addr;
typedef size_t uacpi_size;

typedef va_list uacpi_va_list;
#define uacpi_va_start va_start
#define uacpi_va_end va_end
#define uacpi_va_arg va_arg

typedef char uacpi_char;

#define uacpi_offsetof offsetof

#ifndef __WATCOMC__

/*
 * We use unsignd long long for 64-bit number formatting because 64-bit types
 * don't have a standard way to format them. The inttypes.h header is not
 * freestanding therefore it's not practical to force the user to define the
 * corresponding PRI macros. Moreover, unsignd long long  is required to be
 * at least 64-bits as per C99.
 */
UACPI_BUILD_BUG_ON_WITH_MSG(
    sizeof(unsigned long long) < 8,
    "unsigned long long must be at least 64 bits large as per C99"
);

#endif

#define UACPI_PRIu64 "llu"
#define UACPI_PRIx64 "llx"
#define UACPI_PRIX64 "llX"
#define UACPI_FMT64(val) ((unsigned long long)(val))

#endif
