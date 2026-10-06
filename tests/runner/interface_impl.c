#include "helpers.h"
#include "os.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uacpi/kernel_api.h>
#include <uacpi/status.h>
#include <uacpi/types.h>

uacpi_phys_addr g_rsdp;

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_rsdp_address)
{
    *out_rsdp_address = g_rsdp;
    return UACPI_STATUS_OK;
}

static uint8_t *io_space;

#ifdef UACPI_KERNEL_INITIALIZATION
uacpi_status uacpi_kernel_initialize(uacpi_init_level lvl)
{
    if (lvl == UACPI_INIT_LEVEL_EARLY)
        io_space = do_malloc(UINT16_MAX + 1);
    return UACPI_STATUS_OK;
}

void uacpi_kernel_deinitialize(void)
{
    free(io_space);
    io_space = NULL;
}
#endif

static uacpi_interrupt_state int_state = 1000000;

uacpi_interrupt_state uacpi_kernel_disable_interrupts(void)
{
    uacpi_interrupt_state prev_state = int_state;

    int_state--;
    return prev_state;
}

void uacpi_kernel_restore_interrupts(uacpi_interrupt_state state)
{
    if (state != (int_state - 1)) {
        error(
            "interrupt state mismatch: tried to set %d (expected %d)\n",
            state, int_state - 1
        );
    }

    int_state++;
}

uacpi_status uacpi_kernel_io_map(
    uacpi_io_addr base, uacpi_size len, uacpi_handle *out_handle
)
{
    UACPI_UNUSED(len);

    *out_handle = (uacpi_handle)((uintptr_t)base);
    return UACPI_STATUS_OK;
}

void uacpi_kernel_io_unmap(uacpi_handle handle)
{
    UACPI_UNUSED(handle);
}

#define UACPI_IO_READ(bits)                                                \
    uacpi_status uacpi_kernel_io_read##bits(                               \
        uacpi_handle handle, uacpi_size offset, uacpi_u##bits *out_value   \
    )                                                                      \
    {                                                                      \
        uacpi_io_addr addr = (uacpi_io_addr)((uintptr_t)handle) + offset;  \
                                                                           \
        if (io_space && addr <= UINT16_MAX)                                \
            memcpy(out_value, &io_space[addr], bits / 8);                  \
        else                                                               \
            *out_value = (uacpi_u##bits)0xFFFFFFFFFFFFFFFF;                \
                                                                           \
        return UACPI_STATUS_OK;                                            \
    }

#define UACPI_IO_WRITE(bits)                                              \
    uacpi_status uacpi_kernel_io_write##bits(                             \
        uacpi_handle handle, uacpi_size offset, uacpi_u##bits in_value    \
    )                                                                     \
    {                                                                     \
        uacpi_io_addr addr = (uacpi_io_addr)((uintptr_t)handle) + offset; \
                                                                          \
        if (io_space && addr <= UINT16_MAX)                               \
            memcpy(&io_space[addr], &in_value, bits / 8);                 \
                                                                          \
        return UACPI_STATUS_OK;                                           \
    }

/*
 * A fake PCI topology that lives on its own segment, used to test that devices
 * below bridges are looked up on the correct bus. Every other device (and
 * anything not listed here) reads as all ones.
 *
 * The configuration space of these is plain memory, with one exception: a
 * write to FAKE_PCI_SET_SECONDARY_BUS_REG also sets the secondary bus number.
 * This allows a test to (re)configure a bridge without having to write to its
 * header.
 */
#define FAKE_PCI_SEGMENT 0xCAFE

// Nothing on this bus can be opened
#define FAKE_PCI_BUS_NOT_FOUND 0x1B

#define FAKE_PCI_HEADER_ENDPOINT 0x00
#define FAKE_PCI_HEADER_BRIDGE 0x01
#define FAKE_PCI_HEADER_CARDBUS 0x02
#define FAKE_PCI_HEADER_MULTIFUNCTION 0x80

#define FAKE_PCI_CONFIG_SIZE 0x48
#define FAKE_PCI_SET_SECONDARY_BUS_REG 0x40

typedef struct {
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    uint8_t header_type;
    uint8_t secondary_bus;
    uint32_t id;
} fake_pci_device_t;

static const fake_pci_device_t fake_pci_devices[] = {
    // Nothing is supposed to end up here, the root bus is 0x10
    { 0x00, 0x00, 0, FAKE_PCI_HEADER_ENDPOINT, 0x00, 0xBAD00000 },

    { 0x10, 0x00, 0, FAKE_PCI_HEADER_ENDPOINT, 0x00, 0xA0000000 },
    { 0x10, 0x02, 0, FAKE_PCI_HEADER_ENDPOINT, 0x00, 0xA0000002 },
    { 0x10, 0x03, 0, FAKE_PCI_HEADER_ENDPOINT, 0x00, 0xA0000003 },
    {
        0x10, 0x1C, 0,
        FAKE_PCI_HEADER_BRIDGE | FAKE_PCI_HEADER_MULTIFUNCTION,
        0x15, 0xA000001C,
    },
    /*
     * These two bridges don't lead anywhere until their secondary bus number
     * is set to something else by the test.
     */
    { 0x10, 0x18, 0, FAKE_PCI_HEADER_BRIDGE, 0x00, 0xA0000018 },
    {
        0x10, 0x19, 0,
        FAKE_PCI_HEADER_BRIDGE, FAKE_PCI_BUS_NOT_FOUND, 0xA0000019
    },
    // A bridge that was never configured by the firmware
    { 0x10, 0x1D, 0, FAKE_PCI_HEADER_BRIDGE, 0x00, 0xA000001D },
    { 0x10, 0x1F, 0, FAKE_PCI_HEADER_CARDBUS, 0x19, 0xA000001F },

    { 0x15, 0x00, 0, FAKE_PCI_HEADER_ENDPOINT, 0x00, 0xA0001500 },
    { 0x15, 0x01, 0, FAKE_PCI_HEADER_BRIDGE, 0x16, 0xA0001501 },
    { 0x16, 0x02, 3, FAKE_PCI_HEADER_ENDPOINT, 0x00, 0xA0001623 },
    { 0x19, 0x00, 0, FAKE_PCI_HEADER_ENDPOINT, 0x00, 0xA0001900 },
    { 0x1A, 0x00, 0, FAKE_PCI_HEADER_ENDPOINT, 0x00, 0xA0001A00 },
};

typedef struct {
    bool is_valid;
    uint8_t data[FAKE_PCI_CONFIG_SIZE];
} fake_pci_config_t;

static fake_pci_config_t fake_pci_configs[UACPI_ARRAY_SIZE(fake_pci_devices)];

static fake_pci_config_t *fake_pci_get_config(size_t idx)
{
    const fake_pci_device_t *dev = &fake_pci_devices[idx];
    fake_pci_config_t *config = &fake_pci_configs[idx];

    if (!config->is_valid) {
        memcpy(&config->data[0x00], &dev->id, sizeof(dev->id));
        config->data[0x0E] = dev->header_type;
        config->data[0x18] = dev->bus;
        config->data[0x19] = dev->secondary_bus;
        config->is_valid = true;
    }

    return config;
}

static uint64_t fake_pci_read(
    const fake_pci_config_t *config, uacpi_size offset, uacpi_size width
)
{
    uint64_t value = 0;

    if (offset + width <= sizeof(config->data))
        memcpy(&value, &config->data[offset], width);

    return value;
}

static void fake_pci_write(
    fake_pci_config_t *config, uacpi_size offset, uacpi_size width,
    uint64_t value
)
{
    if (offset + width > sizeof(config->data))
        return;

    memcpy(&config->data[offset], &value, width);

    if (offset <= FAKE_PCI_SET_SECONDARY_BUS_REG &&
        (offset + width) > FAKE_PCI_SET_SECONDARY_BUS_REG)
        config->data[0x19] = config->data[FAKE_PCI_SET_SECONDARY_BUS_REG];
}

#define UACPI_PCI_READ(bits)                                         \
    uacpi_status uacpi_kernel_pci_read##bits(                        \
        uacpi_handle handle, uacpi_size offset, uacpi_u##bits *value \
    )                                                                \
    {                                                                \
        uint64_t ret = 0xFFFFFFFFFFFFFFFF;                           \
                                                                     \
        if (handle != NULL)                                          \
            ret = fake_pci_read(handle, offset, bits / 8);           \
                                                                     \
        *value = (uacpi_u##bits)ret;                                 \
        return UACPI_STATUS_OK;                                      \
    }

#define UACPI_PCI_WRITE(bits)                                       \
    uacpi_status uacpi_kernel_pci_write##bits(                      \
        uacpi_handle handle, uacpi_size offset, uacpi_u##bits value \
    )                                                               \
    {                                                               \
        if (handle != NULL)                                         \
            fake_pci_write(handle, offset, bits / 8, value);        \
                                                                    \
        return UACPI_STATUS_OK;                                     \
    }

#define UACPI_MMIO_READ(bits)                                       \
    uint##bits##_t uacpi_kernel_mmio_read##bits(void *mem)          \
    {                                                               \
        return *(volatile uint##bits##_t*)mem;                      \
    }

#define UACPI_MMIO_WRITE(bits)                                        \
    void uacpi_kernel_mmio_write##bits(void *mem, uint##bits##_t val) \
    {                                                                 \
        *(volatile uint##bits##_t*)mem = val;                         \
    }

UACPI_IO_READ(8)
UACPI_IO_READ(16)
UACPI_IO_READ(32)

UACPI_IO_WRITE(8)
UACPI_IO_WRITE(16)
UACPI_IO_WRITE(32)

UACPI_PCI_READ(8)
UACPI_PCI_READ(16)
UACPI_PCI_READ(32)

UACPI_PCI_WRITE(8)
UACPI_PCI_WRITE(16)
UACPI_PCI_WRITE(32)

#ifdef UACPI_NATIVE_MMIO
UACPI_MMIO_READ(8)
UACPI_MMIO_READ(16)
UACPI_MMIO_READ(32)
UACPI_MMIO_READ(64)

UACPI_MMIO_WRITE(8)
UACPI_MMIO_WRITE(16)
UACPI_MMIO_WRITE(32)
UACPI_MMIO_WRITE(64)
#endif

uacpi_status uacpi_kernel_pci_device_open(
    uacpi_pci_address address, uacpi_handle *out_handle
)
{
    size_t i;

    if (address.segment == 0xDEAD)
        return UACPI_STATUS_NOT_FOUND;

    *out_handle = NULL;

    if (address.segment != FAKE_PCI_SEGMENT)
        return UACPI_STATUS_OK;
    if (address.bus == FAKE_PCI_BUS_NOT_FOUND)
        return UACPI_STATUS_NOT_FOUND;

    for (i = 0; i < UACPI_ARRAY_SIZE(fake_pci_devices); ++i) {
        const fake_pci_device_t *dev = &fake_pci_devices[i];

        if (dev->bus != address.bus || dev->device != address.device ||
            dev->function != address.function)
            continue;

        *out_handle = fake_pci_get_config(i);
        break;
    }

    return UACPI_STATUS_OK;
}

void uacpi_kernel_pci_device_close(uacpi_handle handle)
{
    UACPI_UNUSED(handle);
}

bool g_expect_virtual_addresses = true;

typedef struct {
    hash_node_t node;
    uint64_t phys;
    size_t references;
} virt_location_t;

typedef struct {
    hash_node_t node;
    void *virt;
} mapping_t;

typedef struct {
    hash_node_t node;
    hash_table_t mappings;
} phys_location_t;

static hash_table_t virt_locations;
static hash_table_t phys_locations;

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len)
{
    if (!g_expect_virtual_addresses) {
        phys_location_t *phys_location = HASH_TABLE_FIND(
            &phys_locations, addr, phys_location_t, node
        );
        void *virt;
        virt_location_t *location;
        mapping_t *mapping;

        if (phys_location != NULL) {
            mapping = HASH_TABLE_FIND(
                &phys_location->mappings, len, mapping_t, node
            );

            if (mapping != NULL) {
                location = HASH_TABLE_FIND(
                    &virt_locations, (uintptr_t)mapping->virt, virt_location_t,
                    node
                );

                location->references += 1;
                return mapping->virt;
            }

            printf(
                "WARN: remapping physical 0x%016" PRIX64 " with size %zu\n",
                addr, len
            );
        }

        virt = do_calloc(len, 1);

        location = HASH_TABLE_GET_OR_ADD(
            &virt_locations, (uintptr_t)virt, virt_location_t, node
        );
        location->phys = addr;
        location->references = 1;

        phys_location = HASH_TABLE_GET_OR_ADD(
            &phys_locations, addr, phys_location_t, node
        );
        mapping = HASH_TABLE_GET_OR_ADD(
            &phys_location->mappings, len, mapping_t, node
        );
        mapping->virt = virt;

        return virt;
    }

    return (void*)((uintptr_t)addr);
}

void uacpi_kernel_unmap(void *addr, uacpi_size len)
{
    virt_location_t *virt_location = HASH_TABLE_FIND(
        &virt_locations, (uintptr_t)addr, virt_location_t, node
    );
    phys_location_t *phys_location;
    mapping_t *mapping;

    if (!virt_location)
        return;
    if (--virt_location->references > 0)
        return;

    phys_location = HASH_TABLE_FIND(
        &phys_locations, virt_location->phys, phys_location_t, node
    );
    mapping = HASH_TABLE_FIND(&phys_location->mappings, len, mapping_t, node);
    if (!mapping) {
        printf(
            "WARN: cannot identify mapping virt=%p phys=0x%016" PRIX64 " with "
            "size %zu\n", addr, phys_location->node.key, len
        );
        return;
    }

    HASH_TABLE_REMOVE(&phys_location->mappings, mapping, mapping_t, node);
    if (hash_table_empty(&phys_location->mappings)) {
        hash_table_cleanup(&phys_location->mappings);
        HASH_TABLE_REMOVE(
            &phys_locations, phys_location, phys_location_t, node
        );
    }

    free((void*)((uintptr_t)virt_location->node.key));
    HASH_TABLE_REMOVE(&virt_locations, virt_location, virt_location_t, node);
}

#ifdef UACPI_SIZED_FREES
static hash_table_t allocations;
#endif

void interface_cleanup(void)
{
    size_t i;

    for (i = 0; i < phys_locations.capacity; i++) {
        phys_location_t *location = CONTAINER(
            phys_location_t, node, phys_locations.entries[i]
        );

        while (location) {
            hash_table_cleanup(&location->mappings);
            location = CONTAINER(phys_location_t, node, location->node.next);
        }
    }

    hash_table_cleanup(&phys_locations);
    hash_table_cleanup(&virt_locations);

#ifdef UACPI_SIZED_FREES
    // Make any leaked allocations unreachable so that LSan reports them
    hash_table_cleanup(&allocations);
#endif
}

#ifdef UACPI_SIZED_FREES

typedef struct {
    hash_node_t node;
    size_t size;
} allocation_t;

void *uacpi_kernel_alloc(uacpi_size size)
{
    void *ret;
    allocation_t *allocation;

    if (size == 0)
        abort();

    ret = malloc(size);
    if (ret == NULL)
        return ret;

    allocation = HASH_TABLE_GET_OR_ADD(
        &allocations, (uintptr_t)ret, allocation_t, node
    );
    allocation->size = size;
    return ret;
}

void uacpi_kernel_free(void *mem, uacpi_size size_hint)
{
    allocation_t *allocation;

    if (mem == NULL)
        return;

    allocation = HASH_TABLE_FIND(
        &allocations, (uintptr_t)mem, allocation_t, node
    );
    if (!allocation)
        error("unable to find heap allocation %p\n", mem);

    if (allocation->size != size_hint)
        error(
            "invalid free size: originally allocated %zu bytes, freeing as %zu",
            allocation->size, size_hint
        );

    HASH_TABLE_REMOVE(&allocations, allocation, allocation_t, node);
    free(mem);
}

#else

void *uacpi_kernel_alloc(uacpi_size size)
{
    if (size == 0)
        error("attempted to allocate zero bytes");

    return malloc(size);
}

void uacpi_kernel_free(void *mem)
{
    free(mem);
}

#endif

#ifdef UACPI_NATIVE_ALLOC_ZEROED

void *uacpi_kernel_alloc_zeroed(uacpi_size size)
{
    void *ret = uacpi_kernel_alloc(size);

    if (ret == NULL)
        return ret;

    memset(ret, 0, size);
    return ret;
}

#endif

#ifdef UACPI_FORMATTED_LOGGING

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *format, ...)
{
    va_list args;
    va_start(args, format);

    printf("[uACPI][%s] ", uacpi_log_level_to_string(level));
    vprintf(format, args);

    va_end(args);
}

#else

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *str)
{
    printf("[uACPI][%s] %s", uacpi_log_level_to_string(level), str);
}

#endif

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void)
{
    return get_nanosecond_timer();
}

void uacpi_kernel_stall(uacpi_u8 usec)
{
    uint64_t end = get_nanosecond_timer() + (uint64_t)usec * 1000;

    for (;;)
        if (get_nanosecond_timer() >= end)
            break;
}

void uacpi_kernel_sleep(uacpi_u64 msec)
{
    millisecond_sleep(msec);
}

uacpi_handle uacpi_kernel_create_mutex(void)
{
    mutex_t *mutex = do_malloc(sizeof(*mutex));

    mutex_init(mutex);
    return mutex;
}

void uacpi_kernel_free_mutex(uacpi_handle handle)
{
    mutex_free(handle);
    free(handle);
}

uacpi_thread_id uacpi_kernel_get_thread_id(void)
{
    return get_thread_id();
}

uacpi_status uacpi_kernel_acquire_mutex(uacpi_handle handle, uacpi_u16 timeout)
{
    if (timeout == 0)
        return mutex_try_lock(handle) ? UACPI_STATUS_OK : UACPI_STATUS_TIMEOUT;

    if (timeout == 0xFFFF) {
        mutex_lock(handle);
        return UACPI_STATUS_OK;
    }

    if (mutex_lock_timeout(handle, timeout * 1000000ull))
        return UACPI_STATUS_OK;

    return UACPI_STATUS_TIMEOUT;
}

void uacpi_kernel_release_mutex(uacpi_handle handle)
{
    mutex_unlock(handle);
}

typedef struct {
    mutex_t mutex;
    condvar_t condvar;
    size_t counter;
} event_t;

uacpi_handle uacpi_kernel_create_event(void)
{
    event_t *event = do_calloc(1, sizeof(*event));

    mutex_init(&event->mutex);
    condvar_init(&event->condvar);
    return event;
}

void uacpi_kernel_free_event(uacpi_handle handle)
{
    event_t *event = handle;

    condvar_free(&event->condvar);
    mutex_free(&event->mutex);
    free(handle);
}

static bool event_pred(void *ptr)
{
    event_t *event = ptr;

    return event->counter != 0;
}

uacpi_bool uacpi_kernel_wait_for_event(uacpi_handle handle, uacpi_u16 timeout)
{
    event_t *event = handle;
    bool ok;

    mutex_lock(&event->mutex);

    if (event->counter > 0) {
        event->counter -= 1;
        mutex_unlock(&event->mutex);
        return UACPI_TRUE;
    }

    if (timeout == 0) {
        mutex_unlock(&event->mutex);
        return UACPI_FALSE;
    }

    if (timeout == 0xFFFF) {
        condvar_wait(&event->condvar, &event->mutex, event_pred, event);

        event->counter -= 1;
        mutex_unlock(&event->mutex);
        return UACPI_TRUE;
    }

    ok = condvar_wait_timeout(
        &event->condvar, &event->mutex, event_pred, event, timeout * 1000000ull
    );
    if (ok)
        event->counter -= 1;

    mutex_unlock(&event->mutex);
    return ok ? UACPI_TRUE : UACPI_FALSE;
}

void uacpi_kernel_signal_event(uacpi_handle handle)
{
    event_t *event = handle;

    mutex_lock(&event->mutex);

    event->counter += 1;
    condvar_signal(&event->condvar);

    mutex_unlock(&event->mutex);
}

void uacpi_kernel_reset_event(uacpi_handle handle)
{
    event_t *event = handle;

    mutex_lock(&event->mutex);

    event->counter = 0;

    mutex_unlock(&event->mutex);
}

uacpi_status uacpi_kernel_handle_firmware_request(uacpi_firmware_request *req)
{
    switch (req->type) {
    case UACPI_FIRMWARE_REQUEST_TYPE_BREAKPOINT:
        printf("Ignoring breakpoint\n");
        break;
    case UACPI_FIRMWARE_REQUEST_TYPE_FATAL:
        printf(
            "Fatal firmware error: type: %" PRIx8 " code: %" PRIx32 " arg: "
            "%" PRIx64 "\n", req->fatal.type, req->fatal.code, req->fatal.arg
        );
        break;
    default:
        error("unknown firmware request type %d", req->type);
    }

    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_install_interrupt_handler(
    uacpi_u32 irq, uacpi_interrupt_handler handler, uacpi_handle ctx,
    uacpi_handle *out_irq_handle
)
{
    UACPI_UNUSED(irq);
    UACPI_UNUSED(handler);
    UACPI_UNUSED(ctx);
    UACPI_UNUSED(out_irq_handle);

    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_uninstall_interrupt_handler(
    uacpi_interrupt_handler handler, uacpi_handle irq_handle
)
{
    UACPI_UNUSED(handler);
    UACPI_UNUSED(irq_handle);

    return UACPI_STATUS_OK;
}

uacpi_handle uacpi_kernel_create_spinlock(void)
{
    return uacpi_kernel_create_mutex();
}

void uacpi_kernel_free_spinlock(uacpi_handle handle)
{
    uacpi_kernel_free_mutex(handle);
}

uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle handle)
{
    uacpi_kernel_acquire_mutex(handle, 0xFFFF);
    return 0;
}

void uacpi_kernel_unlock_spinlock(uacpi_handle handle, uacpi_cpu_flags flags)
{
    UACPI_UNUSED(flags);

    uacpi_kernel_release_mutex(handle);
}

uacpi_status uacpi_kernel_schedule_work(
    uacpi_work_type type, uacpi_work_handler handler, uacpi_handle ctx
)
{
    UACPI_UNUSED(type);

    handler(ctx);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void)
{
    return UACPI_STATUS_OK;
}
