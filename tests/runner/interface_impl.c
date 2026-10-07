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

/*
 * Protects the state below that might be accessed by multiple threads at the
 * same time. It's only taken, as well as initialized, if the work threads are
 * running: this is the only way to end up with more than one thread.
 */
static mutex_t interface_mutex;
static bool interface_is_threaded;

static void interface_lock(void)
{
    if (interface_is_threaded)
        mutex_lock(&interface_mutex);
}

static void interface_unlock(void)
{
    if (interface_is_threaded)
        mutex_unlock(&interface_mutex);
}

#define IO_SPACE_SIZE ((size_t)UINT16_MAX + 1)

static uint8_t *io_space;

typedef struct {
    uacpi_io_addr base;
    uacpi_size len;
} io_range_t;

// The first half of every event block is taken by the status registers
static io_range_t io_write_one_to_clear_ranges[8] = {
    { FAKE_PM1A_EVT_BLK, FAKE_PM1_EVT_LEN / 2 },
    { FAKE_GPE0_BLK, FAKE_GPE0_BLK_LEN / 2 },
    { FAKE_GPE1_BLK, FAKE_GPE1_BLK_LEN / 2 },
};
static size_t io_num_write_one_to_clear_ranges = 3;

void fake_io_set_write_one_to_clear(uacpi_io_addr base, uacpi_size len)
{
    io_range_t *range;

    if (io_num_write_one_to_clear_ranges ==
        UACPI_ARRAY_SIZE(io_write_one_to_clear_ranges))
        error("too many write-one-to-clear IO ranges");

    interface_lock();
    range = &io_write_one_to_clear_ranges[io_num_write_one_to_clear_ranges++];
    range->base = base;
    range->len = len;
    interface_unlock();
}

static bool io_is_write_one_to_clear(uacpi_io_addr addr)
{
    size_t i;

    for (i = 0; i < io_num_write_one_to_clear_ranges; ++i) {
        const io_range_t *range = &io_write_one_to_clear_ranges[i];

        if (addr >= range->base && (addr - range->base) < range->len)
            return true;
    }

    return false;
}

static bool io_is_valid(uacpi_io_addr addr, size_t width)
{
    return io_space != NULL && addr < IO_SPACE_SIZE &&
           width <= (IO_SPACE_SIZE - addr);
}

static void io_read(uacpi_io_addr addr, void *out_value, size_t width)
{
    memset(out_value, 0xFF, width);

    if (!io_is_valid(addr, width))
        return;

    interface_lock();
    memcpy(out_value, &io_space[addr], width);
    interface_unlock();
}

static void io_write(uacpi_io_addr addr, const void *value, size_t width)
{
    const uint8_t *bytes = value;
    size_t i;

    if (!io_is_valid(addr, width))
        return;

    interface_lock();

    for (i = 0; i < width; ++i) {
        if (io_is_write_one_to_clear(addr + i))
            io_space[addr + i] &= (uint8_t)~bytes[i];
        else
            io_space[addr + i] = bytes[i];
    }

    interface_unlock();
}

void fake_io_raise(uacpi_io_addr addr, uint8_t bits)
{
    if (!io_is_valid(addr, 1))
        error("invalid IO address 0x%04X", (unsigned)addr);

    interface_lock();
    io_space[addr] |= bits;
    interface_unlock();
}

#ifdef UACPI_KERNEL_INITIALIZATION
uacpi_status uacpi_kernel_initialize(uacpi_init_level lvl)
{
    if (lvl == UACPI_INIT_LEVEL_EARLY) {
        io_space = do_malloc(IO_SPACE_SIZE);

        // Make sure there are no events pending or enabled from the get-go
        memset(&io_space[FAKE_PM1A_EVT_BLK], 0, FAKE_PM1_EVT_LEN);
        memset(&io_space[FAKE_GPE0_BLK], 0, FAKE_GPE0_BLK_LEN);
        memset(&io_space[FAKE_GPE1_BLK], 0, FAKE_GPE1_BLK_LEN);
    }
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
        io_read(addr, out_value, bits / 8);                                \
        return UACPI_STATUS_OK;                                            \
    }

#define UACPI_IO_WRITE(bits)                                              \
    uacpi_status uacpi_kernel_io_write##bits(                             \
        uacpi_handle handle, uacpi_size offset, uacpi_u##bits in_value    \
    )                                                                     \
    {                                                                     \
        uacpi_io_addr addr = (uacpi_io_addr)((uintptr_t)handle) + offset; \
                                                                          \
        io_write(addr, &in_value, bits / 8);                              \
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

static void *do_map(uacpi_phys_addr addr, uacpi_size len)
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

static void do_unmap(void *addr, uacpi_size len)
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

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len)
{
    void *virt;

    interface_lock();
    virt = do_map(addr, len);
    interface_unlock();

    return virt;
}

void uacpi_kernel_unmap(void *addr, uacpi_size len)
{
    interface_lock();
    do_unmap(addr, len);
    interface_unlock();
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

    interface_lock();
    allocation = HASH_TABLE_GET_OR_ADD(
        &allocations, (uintptr_t)ret, allocation_t, node
    );
    allocation->size = size;
    interface_unlock();

    return ret;
}

void uacpi_kernel_free(void *mem, uacpi_size size_hint)
{
    allocation_t *allocation;
    bool is_known = false;
    size_t size = 0;

    if (mem == NULL)
        return;

    interface_lock();
    allocation = HASH_TABLE_FIND(
        &allocations, (uintptr_t)mem, allocation_t, node
    );
    if (allocation != NULL) {
        is_known = true;
        size = allocation->size;
        HASH_TABLE_REMOVE(&allocations, allocation, allocation_t, node);
    }
    interface_unlock();

    if (!is_known)
        error("unable to find heap allocation %p\n", mem);

    if (size != size_hint)
        error(
            "invalid free size: originally allocated %zu bytes, freeing as %zu",
            size, size_hint
        );

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

typedef struct {
    uacpi_u32 irq;
    uacpi_interrupt_handler handler;
    uacpi_handle ctx;
} irq_handler_t;

static irq_handler_t irq_handlers[8];

uacpi_status uacpi_kernel_install_interrupt_handler(
    uacpi_u32 irq, uacpi_interrupt_handler handler, uacpi_handle ctx,
    uacpi_handle *out_irq_handle
)
{
    irq_handler_t *slot = NULL;
    size_t i;

    interface_lock();

    for (i = 0; i < UACPI_ARRAY_SIZE(irq_handlers); ++i) {
        if (irq_handlers[i].handler != NULL)
            continue;

        slot = &irq_handlers[i];
        slot->irq = irq;
        slot->handler = handler;
        slot->ctx = ctx;
        break;
    }

    interface_unlock();

    if (slot == NULL)
        return UACPI_STATUS_OUT_OF_MEMORY;

    *out_irq_handle = slot;
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_uninstall_interrupt_handler(
    uacpi_interrupt_handler handler, uacpi_handle irq_handle
)
{
    irq_handler_t *slot = irq_handle;
    bool is_valid;

    interface_lock();

    is_valid = slot >= &irq_handlers[0] &&
               slot < &irq_handlers[UACPI_ARRAY_SIZE(irq_handlers)] &&
               slot->handler == handler;
    if (is_valid)
        memset(slot, 0, sizeof(*slot));

    interface_unlock();

    if (!is_valid)
        error("attempted to uninstall a bogus interrupt handler");

    return UACPI_STATUS_OK;
}

uacpi_interrupt_ret fake_irq_raise(uacpi_u32 irq)
{
    uacpi_interrupt_ret ret = UACPI_INTERRUPT_NOT_HANDLED;
    irq_handler_t handlers[UACPI_ARRAY_SIZE(irq_handlers)];
    size_t i;

    /*
     * The handlers are invoked by the calling thread, which is as close as we
     * can get to an interrupt context. Do that without holding the lock, as
     * pretty much everything a handler might do needs it.
     */
    interface_lock();
    memcpy(handlers, irq_handlers, sizeof(handlers));
    interface_unlock();

    for (i = 0; i < UACPI_ARRAY_SIZE(handlers); ++i) {
        if (handlers[i].handler == NULL || handlers[i].irq != irq)
            continue;

        ret |= handlers[i].handler(handlers[i].ctx);
    }

    return ret;
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

#define WORK_TIMEOUT_SECONDS 30

typedef struct work {
    struct work *next;
    uacpi_work_handler handler;
    uacpi_handle ctx;
} work_t;

typedef struct {
    thread_t thread;
    void *thread_id;
    condvar_t has_work;
    work_t *head;
    work_t *tail;
} work_queue_t;

/*
 * One thread per work type, indexed by uacpi_work_type. This is what most
 * kernels do, and what makes it possible for a GPE handler to execute at the
 * same time as a notify handler.
 */
static work_queue_t work_queues[UACPI_WORK_NOTIFICATION + 1];

static mutex_t work_mutex;
static condvar_t work_done;
static condvar_t work_watchdog_stop;
static thread_t work_watchdog;

// The amount of work that is either queued or is being executed right now
static size_t work_num_pending;
static bool work_is_held;
static bool work_is_stopping;

/*
 * We can't use error() once the work threads are running: it resets the state
 * of uACPI, which is not possible to do while another thread is inside of it.
 */
NORETURN static void work_fatal(const char *reason)
{
    fflush(stdout);
    fprintf(stderr, "unexpected error: %s\n", reason);
    exit(1);
}

static bool work_queue_should_wake(void *opaque)
{
    work_queue_t *queue = opaque;

    return work_is_stopping || (!work_is_held && queue->head != NULL);
}

static void work_thread(void *opaque)
{
    work_queue_t *queue = opaque;
    work_t *work;

    mutex_lock(&work_mutex);
    queue->thread_id = get_thread_id();

    for (;;) {
        condvar_wait(
            &queue->has_work, &work_mutex, work_queue_should_wake, queue
        );

        // We're only asked to stop after all of the work is done
        if (work_is_stopping)
            break;

        work = queue->head;
        queue->head = work->next;
        mutex_unlock(&work_mutex);

        work->handler(work->ctx);
        free(work);

        mutex_lock(&work_mutex);
        if (--work_num_pending == 0)
            condvar_broadcast(&work_done);
    }

    mutex_unlock(&work_mutex);
}

static bool work_watchdog_should_stop(void *opaque)
{
    UACPI_UNUSED(opaque);
    return work_is_stopping;
}

static void work_watchdog_thread(void *opaque)
{
    bool stopped;

    UACPI_UNUSED(opaque);

    mutex_lock(&work_mutex);
    stopped = condvar_wait_timeout(
        &work_watchdog_stop, &work_mutex, work_watchdog_should_stop, NULL,
        WORK_TIMEOUT_SECONDS * NANOSECONDS_PER_SECOND
    );
    mutex_unlock(&work_mutex);

    if (!stopped) {
        work_fatal(
            "the work threads were not stopped in time, the test has most "
            "likely deadlocked"
        );
    }
}

/*
 * The C library of OpenWatcom is of no use to a program with more than one
 * thread, at least not on Linux: a call to malloc() that is made by a few
 * threads at once is enough to corrupt the heap, and pthread_join() is prone
 * to never coming back.
 */
static bool work_threads_supported(void)
{
#ifdef __WATCOMC__
    return false;
#else
    return true;
#endif
}

void work_threads_start(void)
{
    size_t i;

    if (interface_is_threaded)
        error("the work threads are already running");

    if (!work_threads_supported()) {
        printf("no usable threads here, skipping the rest of the test\n");
        exit(0);
    }

    mutex_init(&interface_mutex);
    mutex_init(&work_mutex);
    condvar_init(&work_done);
    condvar_init(&work_watchdog_stop);

    work_is_held = false;
    work_is_stopping = false;
    interface_is_threaded = true;

    for (i = 0; i < UACPI_ARRAY_SIZE(work_queues); ++i) {
        work_queue_t *queue = &work_queues[i];

        condvar_init(&queue->has_work);
        thread_create(&queue->thread, work_thread, queue);
    }

    thread_create(&work_watchdog, work_watchdog_thread, NULL);
}

static void work_release_locked(void)
{
    size_t i;

    work_is_held = false;

    for (i = 0; i < UACPI_ARRAY_SIZE(work_queues); ++i)
        condvar_signal(&work_queues[i].has_work);
}

void work_threads_stop(void)
{
    size_t i;

    if (!interface_is_threaded)
        error("the work threads are not running");

    uacpi_kernel_wait_for_work_completion();

    mutex_lock(&work_mutex);
    work_is_stopping = true;
    work_release_locked();
    condvar_signal(&work_watchdog_stop);
    mutex_unlock(&work_mutex);

    for (i = 0; i < UACPI_ARRAY_SIZE(work_queues); ++i) {
        work_queue_t *queue = &work_queues[i];

        thread_join(&queue->thread);
        condvar_free(&queue->has_work);
        queue->thread_id = NULL;
    }
    thread_join(&work_watchdog);

    interface_is_threaded = false;

    condvar_free(&work_watchdog_stop);
    condvar_free(&work_done);
    mutex_free(&work_mutex);
    mutex_free(&interface_mutex);
}

void work_hold(void)
{
    if (!interface_is_threaded)
        error("work can only be held if the work threads are running");

    mutex_lock(&work_mutex);
    work_is_held = true;
    mutex_unlock(&work_mutex);
}

void work_release(void)
{
    if (!interface_is_threaded)
        error("work can only be released if the work threads are running");

    mutex_lock(&work_mutex);
    work_release_locked();
    mutex_unlock(&work_mutex);
}

uacpi_status uacpi_kernel_schedule_work(
    uacpi_work_type type, uacpi_work_handler handler, uacpi_handle ctx
)
{
    work_queue_t *queue;
    work_t *work;

    if (!interface_is_threaded) {
        handler(ctx);
        return UACPI_STATUS_OK;
    }

    if ((size_t)type >= UACPI_ARRAY_SIZE(work_queues))
        return UACPI_STATUS_INVALID_ARGUMENT;

    work = do_calloc(1, sizeof(*work));
    work->handler = handler;
    work->ctx = ctx;

    mutex_lock(&work_mutex);

    queue = &work_queues[type];
    if (queue->head == NULL)
        queue->head = work;
    else
        queue->tail->next = work;
    queue->tail = work;

    work_num_pending++;
    if (!work_is_held)
        condvar_signal(&queue->has_work);

    mutex_unlock(&work_mutex);
    return UACPI_STATUS_OK;
}

static bool work_is_done(void *opaque)
{
    UACPI_UNUSED(opaque);
    return work_num_pending == 0;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void)
{
    void *this_id;
    size_t i;

    if (!interface_is_threaded)
        return UACPI_STATUS_OK;

    this_id = get_thread_id();
    mutex_lock(&work_mutex);

    for (i = 0; i < UACPI_ARRAY_SIZE(work_queues); ++i) {
        if (work_queues[i].thread_id != this_id)
            continue;

        work_fatal(
            "a work handler has attempted to wait for work completion, "
            "which would never return"
        );
    }

    /*
     * There are no in-flight interrupts to wait for, as an interrupt handler
     * is never invoked asynchronously.
     *
     * Someone is waiting for the work, so there's no point in holding it any
     * longer: this is exactly what the hold is there to wait for.
     */
    work_release_locked();
    condvar_wait(&work_done, &work_mutex, work_is_done, NULL);

    mutex_unlock(&work_mutex);
    return UACPI_STATUS_OK;
}
