#pragma once

#include <uacpi/helpers.h>

#define UACPI_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifdef __WATCOMC__
#define UACPI_UNUSED(x)
#else
#define UACPI_UNUSED(x) (void)(x)
#endif
