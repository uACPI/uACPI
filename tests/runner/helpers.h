#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <uacpi/acpi.h>
#include <uacpi/internal/helpers.h>
#include <uacpi/status.h>
#include <uacpi/uacpi.h>

#ifdef __GNUC__
#define NORETURN __attribute__((__noreturn__))
#else
#define NORETURN
#endif

NORETURN static inline void error(const char *format, ...)
{
    va_list args;

    fprintf(stderr, "unexpected error: ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputc('\n', stderr);
    uacpi_state_reset();
    exit(1);
}

static inline void *do_malloc(size_t size)
{
    void *ptr = malloc(size);

    if (!ptr)
        error("failed to allocate %zu bytes of memory", size);
    return ptr;
}

static inline void *do_calloc(size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);

    if (!ptr)
        error("failed to allocate %zu bytes of memory", nmemb * size);
    return ptr;
}

static inline void *do_realloc(void *ptr, size_t size)
{
    ptr = realloc(ptr, size);

    if (!ptr)
        error("failed to allocate %zu bytes of memory", size);
    return ptr;
}

typedef struct {
    void *data;
    size_t size;
} blob_t;

typedef struct {
    blob_t *blobs;
    size_t capacity;
    size_t count;
} vector_t;

static inline void vector_init(vector_t *vector, size_t items)
{
    vector->blobs = do_calloc(items, sizeof(*vector->blobs));
    vector->capacity = items;
    vector->count = items;
}

static inline void vector_add(vector_t *vector, void *data, size_t size)
{
    if (vector->count >= vector->capacity) {
        vector->capacity = vector->capacity ? vector->capacity * 2 : 8;
        vector->blobs = do_realloc(
            vector->blobs, vector->capacity * sizeof(*vector->blobs)
        );
    }

    vector->blobs[vector->count].data = data;
    vector->blobs[vector->count].size = size;
    vector->count += 1;
}

static inline void vector_cleanup(vector_t *vector)
{
    free(vector->blobs);
    vector->capacity = 0;
    vector->count = 0;
}

static inline void *get_container(void *value, size_t offset)
{
    return value ? (void*)((char*)value - offset) : NULL;
}

#define CONTAINER(type, field, value) \
    ((type*)get_container((value), offsetof(type, field)))

typedef struct hash_node {
    struct hash_node *prev;
    struct hash_node *next;
    uint64_t key;
} hash_node_t;

typedef struct {
    hash_node_t **entries;
    size_t capacity;
    size_t count;
} hash_table_t;

static inline uint64_t make_hash(uint64_t x)
{
    x *= 0xe9770214b82cf957;
    x ^= x >> 47;
    x *= 0x2bdd9d20d060fc9b;
    x ^= x >> 44;
    x *= 0x65c487023b406173;
    return x;
}

static inline hash_node_t *hash_table_find(hash_table_t *table, uint64_t key)
{
    hash_node_t *current;

    if (!table->capacity)
        return NULL;

    current = table->entries[make_hash(key) % table->capacity];

    while (current != NULL && current->key != key)
        current = current->next;

    return current;
}

#define HASH_TABLE_FIND(table, key, type, field) \
    CONTAINER(type, field, hash_table_find((table), (key)))

static inline hash_node_t *hash_table_get_or_add(
        hash_table_t *table, uint64_t key, size_t size, size_t offset
)
{
    uint64_t hash = make_hash(key);
    void *value;
    hash_node_t *node;
    size_t bucket;

    if (table->capacity) {
        hash_node_t *current = table->entries[hash % table->capacity];

        while (current != NULL) {
            if (current->key == key)
                return current;
            current = current->next;
        }
    }

    if (table->count >= table->capacity - (table->capacity / 4)) {
        size_t new_cap = table->capacity ? table->capacity * 2 : 8;
        hash_node_t **new_entries = do_calloc(new_cap, sizeof(*table->entries));
        size_t i;

        for (i = 0; i < table->capacity; i++) {
            hash_node_t *current = table->entries[i];

            while (current != NULL) {
                hash_node_t *next = current->next;
                size_t bucket = make_hash(current->key) % new_cap;

                current->prev = NULL;
                current->next = new_entries[bucket];
                if (current->next)
                    current->next->prev = current;
                new_entries[bucket] = current;

                current = next;
            }
        }

        free(table->entries);
        table->entries = new_entries;
        table->capacity = new_cap;
    }

    value = do_calloc(1, size);
    node = (void*)((char*)value + offset);
    node->key = key;

    bucket = hash % table->capacity;
    node->prev = NULL;
    node->next = table->entries[bucket];
    if (node->next)
        node->next->prev = node;
    table->entries[bucket] = node;

    table->count += 1;

    return node;
}

#define HASH_TABLE_GET_OR_ADD(table, key, type, field)          \
    CONTAINER(                                                  \
        type, field,                                            \
        hash_table_get_or_add(                                  \
            (table), (key), sizeof(type), offsetof(type, field) \
        )                                                       \
    )

static inline void hash_table_remove(
    hash_table_t *table, hash_node_t *node, size_t offset
)
{
    if (node->prev)
        node->prev->next = node->next;
    else
        table->entries[make_hash(node->key) % table->capacity] = node->next;

    if (node->next)
        node->next->prev = node->prev;

    table->count -= 1;
    free((void*)((char*)node - offset));
}

#define HASH_TABLE_REMOVE(table, value, type, field) \
    hash_table_remove((table), &(value)->field, offsetof(type, field))

static inline bool hash_table_empty(hash_table_t *table)
{
    return table->count == 0;
}

static inline void hash_table_cleanup(hash_table_t *table)
{
    free(table->entries);
    table->capacity = 0;
    table->count = 0;
}

extern bool g_expect_virtual_addresses;
extern uacpi_phys_addr g_rsdp;

UACPI_PACKED(struct full_xsdt {
    struct acpi_sdt_hdr hdr;
    struct acpi_fadt *fadt;
    struct acpi_sdt_hdr *ssdts[];
})

void set_oem(char (*oemid)[6]);
void set_oem_table_id(char (*oemid_table_id)[8]);

struct full_xsdt *make_xsdt(
    struct acpi_rsdp *rsdp, const char *dsdt_path, const vector_t *ssdt_paths
);
struct full_xsdt *make_xsdt_blob(
    struct acpi_rsdp *rsdp, const void *dsdt, size_t dsdt_size
);
void delete_xsdt(struct full_xsdt *xsdt, size_t num_tables);

blob_t read_entire_file(const char *path, size_t min_size);

static inline void ensure_ok_status(uacpi_status st)
{
    if (st == UACPI_STATUS_OK)
        return;

    error("uACPI error: %s", uacpi_status_to_string(st));
}

static inline const char *uacpi_log_level_to_string(uacpi_log_level lvl)
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
        abort();
        return NULL;
    }
}
