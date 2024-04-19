#pragma once

#include <uacpi/types.h>
#include <uacpi/internal/stdlib.h>
#include <uacpi/kernel_api.h>

#define DYNAMIC_ARRAY_WITH_INLINE_STORAGE(name, type, inline_capacity)       \
    struct name {                                                            \
        type inline_storage[inline_capacity];                                \
        type *dynamic_storage;                                               \
        uacpi_size dynamic_capacity;                                         \
        uacpi_size size_including_inline;                                    \
    };                                                                       \

#define DYNAMIC_ARRAY_SIZE(arr) ((arr)->size_including_inline)

#define DYNAMIC_ARRAY_WITH_INLINE_STORAGE_EXPORTS(name, type, prefix) \
    prefix uacpi_size name##_inline_capacity(struct name *arr);       \
    prefix type *name##_at(struct name *arr, uacpi_size idx);         \
    prefix type *name##_alloc(struct name *arr);                      \
    prefix type *name##_calloc(struct name *arr);                     \
    prefix void name##_pop(struct name *arr);                         \
    prefix uacpi_size name##_size(struct name *arr);                  \
    prefix type *name##_last(struct name *arr)                        \
    prefix void name##_clear(struct name *arr);

#define DYNAMIC_ARRAY_WITH_INLINE_STORAGE_IMPL(name, type, prefix)           \
    UACPI_MAYBE_UNUSED                                                       \
    prefix uacpi_size name##_inline_capacity(struct name *arr)               \
    {                                                                        \
        return sizeof(arr->inline_storage) / sizeof(arr->inline_storage[0]); \
    }                                                                        \
                                                                             \
    prefix type *name##_at(struct name *arr, uacpi_size idx)                 \
    {                                                                        \
        if (idx >= arr->size_including_inline)                               \
            return UACPI_NULL;                                               \
                                                                             \
        if (idx < name##_inline_capacity(arr))                               \
            return &arr->inline_storage[idx];                                \
                                                                             \
        return &arr->dynamic_storage[idx - name##_inline_capacity(arr)];     \
    }                                                                        \
                                                                             \
    UACPI_MAYBE_UNUSED                                                       \
    prefix type *name##_alloc(struct name *arr)                              \
    {                                                                        \
        uacpi_size inline_cap;                                               \
        type *out_ptr;                                                       \
                                                                             \
        inline_cap = name##_inline_capacity(arr);                            \
                                                                             \
        if (arr->size_including_inline >= inline_cap) {                      \
            uacpi_size dynamic_size;                                         \
                                                                             \
            dynamic_size = arr->size_including_inline - inline_cap;          \
            if (dynamic_size == arr->dynamic_capacity) {                     \
                uacpi_size bytes, type_size;                                 \
                void *new_buf;                                               \
                                                                             \
                type_size = sizeof(*arr->dynamic_storage);                   \
                bytes = arr->dynamic_capacity * type_size;                   \
                bytes += type_size;                                          \
                                                                             \
                new_buf = uacpi_kernel_alloc(bytes);                         \
                if (!new_buf)                                                \
                    return NULL;                                             \
                arr->dynamic_capacity = bytes / type_size;                   \
                                                                             \
                if (arr->dynamic_storage) {                                  \
                    uacpi_memcpy(new_buf, arr->dynamic_storage,              \
                                 dynamic_size * type_size);                  \
                }                                                            \
                uacpi_free(arr->dynamic_storage, dynamic_size * type_size);  \
                arr->dynamic_storage = new_buf;                              \
            }                                                                \
                                                                             \
            out_ptr = &arr->dynamic_storage[dynamic_size];                   \
            goto ret;                                                        \
        }                                                                    \
                                                                             \
                                                                             \
        out_ptr = &arr->inline_storage[arr->size_including_inline];          \
                                                                             \
    ret:                                                                     \
        arr->size_including_inline++;                                        \
        return out_ptr;                                                      \
    }                                                                        \
                                                                             \
    UACPI_MAYBE_UNUSED                                                       \
    prefix type *name##_calloc(struct name *arr)                             \
    {                                                                        \
        type *ret;                                                           \
                                                                             \
        ret = name##_alloc(arr);                                             \
        if (ret)                                                             \
            uacpi_memzero(ret, sizeof(*ret));                                \
                                                                             \
        return ret;                                                          \
    }                                                                        \
                                                                             \
    UACPI_MAYBE_UNUSED                                                       \
    prefix void name##_pop(struct name *arr)                                 \
    {                                                                        \
        if (arr->size_including_inline == 0)                                 \
            return;                                                          \
                                                                             \
        arr->size_including_inline--;                                        \
    }                                                                        \
                                                                             \
    UACPI_MAYBE_UNUSED                                                       \
    prefix uacpi_size name##_size(struct name *arr)                          \
    {                                                                        \
        return arr->size_including_inline;                                   \
    }                                                                        \
                                                                             \
    UACPI_MAYBE_UNUSED                                                       \
    prefix type *name##_last(struct name *arr)                               \
    {                                                                        \
        return name##_at(arr, arr->size_including_inline - 1);               \
    }                                                                        \
                                                                             \
    prefix void name##_clear(struct name *arr)                               \
    {                                                                        \
        uacpi_free(                                                          \
            arr->dynamic_storage,                                            \
            arr->dynamic_capacity * sizeof(*arr->dynamic_storage)            \
        );                                                                   \
        arr->size_including_inline = 0;                                      \
        arr->dynamic_capacity = 0;                                           \
    }
