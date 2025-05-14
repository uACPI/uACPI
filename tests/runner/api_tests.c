#include "helpers.h"
#include <inttypes.h>
#include <string.h>
#include <uacpi/opregion.h>
#include <uacpi/resources.h>
#include <uacpi/types.h>

static void check_ok(uacpi_object **objects, uacpi_object_array *arr)
{
    uacpi_u64 ret;
    uacpi_status st = uacpi_eval_integer(UACPI_NULL, "CHEK", arr, &ret);

    ensure_ok_status(st);
    if (!ret)
        error("integer check failed");
    uacpi_object_unref(objects[1]);
}

void test_object_api(void)
{
    uacpi_status st;
    uacpi_object_array arr;
    uacpi_object *objects[2];
    uacpi_data_view view;
    uacpi_object *tmp;
    uint8_t buffer[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uacpi_object *pkg[3];
    uacpi_object_array arr1;

    arr.objects = objects;
    arr.count = UACPI_ARRAY_SIZE(objects);
    objects[0] = uacpi_object_create_integer(1);

    st = uacpi_object_create_integer_safe(
        0xDEADBEEFDEADBEEF, UACPI_OVERFLOW_DISALLOW, &objects[1]
    );
    if (st != UACPI_STATUS_INVALID_ARGUMENT)
        error("expected integer creation to fail");

    objects[1] = uacpi_object_create_integer(0xDEADBEEF);
    check_ok(objects, &arr);

    st = uacpi_object_assign_integer(objects[0], 2);
    ensure_ok_status(st);

    objects[1] = uacpi_object_create_cstring("Hello World");
    uacpi_object_ref(objects[1]);
    check_ok(objects, &arr);

    view.const_text = "Hello World";
    // Don't include the null byte to check if this is accounted for
    view.length = 11;

    uacpi_object_assign_string(objects[1], view);
    check_ok(objects, &arr);

    st = uacpi_object_assign_integer(objects[0], 3);
    ensure_ok_status(st);
    tmp = uacpi_object_create_cstring("XXXX");
    objects[1] = uacpi_object_create_reference(tmp);
    uacpi_object_unref(tmp);
    check_ok(objects, &arr);

    st = uacpi_object_assign_integer(objects[0], 4);
    ensure_ok_status(st);
    view.const_bytes = buffer;
    view.length = sizeof(buffer);
    objects[1] = uacpi_object_create_buffer(view);
    check_ok(objects, &arr);

    st = uacpi_object_assign_integer(objects[0], 5);
    ensure_ok_status(st);

    pkg[0] = uacpi_object_create_uninitialized();
    view.const_text = "First Element";
    view.length = strlen(view.const_text);
    uacpi_object_assign_string(pkg[0], view);

    pkg[1] = uacpi_object_create_cstring("test");
    st = uacpi_object_assign_integer(pkg[1], 2);
    ensure_ok_status(st);

    buffer[0] = 1;
    buffer[1] = 2;
    buffer[2] = 3;
    view.const_bytes = buffer;
    view.length = 3;
    pkg[2] = uacpi_object_create_buffer(view);
    st = uacpi_object_assign_buffer(pkg[2], view);

    arr1.objects = pkg;
    arr1.count = 3;
    objects[1] = uacpi_object_create_package(arr1);
    uacpi_object_assign_package(objects[1], arr1);
    check_ok(objects, &arr);
    uacpi_object_unref(pkg[0]);
    uacpi_object_unref(pkg[1]);
    uacpi_object_unref(pkg[2]);

    uacpi_object_unref(objects[0]);
}

#define CHECK_VALUE(x, y) \
    if ((x) != (y))       \
        error("check at %d failed", __LINE__);
#define CHECK_STRING(x, y) \
    if (strcmp((x), (y)))  \
        error("check at %d failed", __LINE__);

static void eval_one(uacpi_object *arg, uacpi_address_space type)
{
    uacpi_object_array arr = { 0 };
    uacpi_u64 out_value;
    uacpi_status st;

    arr.objects = &arg;
    arr.count = 1;

    st = uacpi_object_assign_integer(arg, type);
    ensure_ok_status(st);
    st = uacpi_eval_integer(NULL, "CHEK", &arr, &out_value);
    ensure_ok_status(st);

    if (!out_value)
        error("%s test failed", uacpi_address_space_to_string(type));
}

static uacpi_status ipmi_handler(uacpi_region_op op, uacpi_handle op_data)
{
    uacpi_region_ipmi_rw_data *ipmi = op_data;
    uint64_t response;
    const char *command;

    if (op == UACPI_REGION_OP_ATTACH || op == UACPI_REGION_OP_DETACH)
        return UACPI_STATUS_OK;
    CHECK_VALUE(op, UACPI_REGION_OP_IPMI_COMMAND);

    CHECK_VALUE(ipmi->in_out_message.length, 66);

    command = ipmi->in_out_message.const_text;
    if (!strcmp(command, "IPMICommandDEADBEE0"))
        response = 0xDEADBEE0;
    else if (!strcmp(command, "IPMICommandDEADBEEF"))
        response = 0xDEADBEEF;
    else
        error("invalid IPMI command %s", command);

    CHECK_VALUE(ipmi->command, response);

    memcpy(ipmi->in_out_message.data, &response, sizeof(response));
    return UACPI_STATUS_OK;
}

static uacpi_status gpio_handler(uacpi_region_op op, uacpi_handle op_data)
{
    uacpi_region_gpio_rw_data *rw_data = op_data;
    uacpi_resource *res;
    uacpi_status ret;
    uacpi_resource_gpio_connection *gpio;
    uacpi_namespace_node *gpio_node;
    uacpi_u64 bit_offset;
    uacpi_u64 *state;
    uacpi_u64 i;

    switch (op) {
    case UACPI_REGION_OP_ATTACH: {
        uacpi_region_attach_data *att_data = op_data;

        CHECK_VALUE(att_data->gpio_info.num_pins, 6);
        att_data->out_region_context = do_calloc(1, sizeof(uint64_t));
        return UACPI_STATUS_OK;
    }
    case UACPI_REGION_OP_DETACH: {
        uacpi_region_detach_data *det_data = op_data;

        free(det_data->region_context);
        return UACPI_STATUS_OK;
    }
    default:
        break;
    }

    ret = uacpi_get_resource_from_buffer(rw_data->connection, &res);
    ensure_ok_status(ret);

    CHECK_VALUE(res->type, UACPI_RESOURCE_TYPE_GPIO_CONNECTION);
    gpio = &res->gpio_connection;

    ret = uacpi_namespace_node_find(NULL, gpio->source.string, &gpio_node);
    ensure_ok_status(ret);

    ret = uacpi_eval_simple_integer(gpio_node, "_UID", &bit_offset);
    ensure_ok_status(ret);

    bit_offset *= 16;
    state = rw_data->region_context;

    if (rw_data->num_pins == 0 || rw_data->num_pins > 3)
        error("bogus number of pins %d", rw_data->num_pins);

    if (op == UACPI_REGION_OP_GPIO_READ)
        rw_data->value = 0;

    for (i = 0; i < rw_data->num_pins; ++i) {
        uint64_t abs_pin = i + rw_data->pin_offset;
        bool value;

        if (op == UACPI_REGION_OP_GPIO_READ) {
            value = (*state >> bit_offset) & (1ull << abs_pin);

            if (value)
                rw_data->value |= (1ull << i);
        } else {
            unsigned long long mask = 1ull << abs_pin;

            CHECK_VALUE(op, UACPI_REGION_OP_GPIO_WRITE);
            value = rw_data->value & (1ull << i);

            if (value)
                *state |= mask;
            else
                *state &= ~mask;
        }
    }

    uacpi_free_resource(res);
    return UACPI_STATUS_OK;
}

static uacpi_status pcc_handler(uacpi_region_op op, uacpi_handle op_data)
{
    uacpi_region_pcc_send_data *rw_data = op_data;
    uint32_t x;

    if (op == UACPI_REGION_OP_ATTACH) {
        uacpi_region_attach_data *att_data = op_data;

        CHECK_VALUE(att_data->pcc_info.buffer.length, 0xFF);
        CHECK_VALUE(att_data->pcc_info.subspace_id, 0xCA)

        att_data->out_region_context = att_data->pcc_info.buffer.data;
        return UACPI_STATUS_OK;
    }

    if (op == UACPI_REGION_OP_DETACH)
        return UACPI_STATUS_OK;
    CHECK_VALUE(op, UACPI_REGION_OP_PCC_SEND);

    CHECK_VALUE(rw_data->buffer.data, rw_data->region_context);
    CHECK_STRING(rw_data->buffer.const_text, "HELLO");

    memcpy(&x, rw_data->buffer.bytes + 12, sizeof(x));
    CHECK_VALUE(x, 0xDEADBEEF);

    x = 0xBEEFDEAD;
    memcpy(rw_data->buffer.bytes + 12, &x, sizeof(x));

    return UACPI_STATUS_OK;
}

static uacpi_status prm_handler(uacpi_region_op op, uacpi_handle op_data)
{
    static const char response[] = "goodbyeworld";
    uacpi_region_prm_rw_data *rw_data = op_data;

    if (op == UACPI_REGION_OP_ATTACH || op == UACPI_REGION_OP_DETACH)
        return UACPI_STATUS_OK;
    CHECK_VALUE(op, UACPI_REGION_OP_PRM_COMMAND);

    CHECK_VALUE(rw_data->in_out_message.length, 26);
    CHECK_STRING(rw_data->in_out_message.const_text, "helloworld");

    memcpy(rw_data->in_out_message.text, response, sizeof(response));

    return UACPI_STATUS_OK;
}

static uacpi_status ffixedhw_handler(uacpi_region_op op, uacpi_handle op_data)
{
    static const char response[] = "ok";
    uacpi_region_ffixedhw_rw_data *rw_data = op_data;

    if (op == UACPI_REGION_OP_ATTACH) {
        uacpi_region_attach_data *att_data = op_data;

        CHECK_VALUE(att_data->generic_info.base, 0xCAFEBABE);
        CHECK_VALUE(att_data->generic_info.length, 0xFEFECACA)
        return UACPI_STATUS_OK;
    }

    if (op == UACPI_REGION_OP_DETACH)
        return UACPI_STATUS_OK;
    CHECK_VALUE(op, UACPI_REGION_OP_FFIXEDHW_COMMAND);

    CHECK_VALUE(rw_data->in_out_message.length, 256);
    CHECK_STRING(rw_data->in_out_message.const_text, "someguidandstuff");

    memcpy(rw_data->in_out_message.text, "ok", sizeof(response));

    return UACPI_STATUS_OK;
}

static uacpi_status generic_serial_bus_handler(
    uacpi_region_op op, uacpi_handle op_data
)
{
    uacpi_region_serial_rw_data *rw_data = op_data;
    uacpi_resource *res;
    uacpi_status ret;
    uacpi_resource_i2c_connection *gpio;
    uacpi_namespace_node *i2c_node;
    uacpi_u64 i2c_offset;
    uacpi_u16 response;

    if (op == UACPI_REGION_OP_ATTACH || op == UACPI_REGION_OP_DETACH)
        return UACPI_STATUS_OK;
    CHECK_VALUE(
        true, (op == UACPI_REGION_OP_SERIAL_READ ||
               op == UACPI_REGION_OP_SERIAL_WRITE)
    );

    ret = uacpi_get_resource_from_buffer(rw_data->connection, &res);
    ensure_ok_status(ret);

    CHECK_VALUE(res->type, UACPI_RESOURCE_TYPE_SERIAL_I2C_CONNECTION);
    gpio = &res->i2c_connection;

    ret = uacpi_namespace_node_find(
        NULL, gpio->common.source.string, &i2c_node
    );
    ensure_ok_status(ret);

    ret = uacpi_eval_simple_integer(i2c_node, "_UID", &i2c_offset);
    ensure_ok_status(ret);

    switch ((int)rw_data->command) {
    case 0x111:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_WRITE);
        CHECK_VALUE(i2c_offset, 0);
        CHECK_VALUE(rw_data->in_out_buffer.length, 2);
        CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_QUICK);
        break;
    case 0x121:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_WRITE);
        CHECK_VALUE(i2c_offset, 0);
        CHECK_VALUE(rw_data->in_out_buffer.length, 3);
        CHECK_VALUE(
            rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_SEND_RECEIVE
        );
        break;
    case 0x122:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_WRITE);
        CHECK_VALUE(i2c_offset, 0);
        CHECK_VALUE(rw_data->in_out_buffer.length, 3);
        CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_BYTE);
        break;
    case 0x124:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_READ);
        CHECK_VALUE(i2c_offset, 0);
        CHECK_VALUE(rw_data->in_out_buffer.length, 4);
        CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_WORD);
        break;
    case 0x128:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_READ);
        CHECK_VALUE(i2c_offset, 0);
        CHECK_VALUE(rw_data->in_out_buffer.length, 257);
        CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_BLOCK);
        break;
    case 0x228:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_WRITE);
        CHECK_VALUE(i2c_offset, 0);
        CHECK_VALUE(rw_data->in_out_buffer.length, 4);
        CHECK_VALUE(
            rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_PROCESS_CALL
        );
        break;
    case 0x229:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_READ);
        CHECK_VALUE(i2c_offset, 0);
        CHECK_VALUE(rw_data->in_out_buffer.length, 257);
        CHECK_VALUE(
            rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_BLOCK_PROCESS_CALL
        );
        break;
    case 0x23B:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_WRITE);
        CHECK_VALUE(i2c_offset, 1);
        CHECK_VALUE(rw_data->in_out_buffer.length, 17);
        CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_BYTES);
        CHECK_VALUE(rw_data->access_length, 15);
        break;
    case 0x23C:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_READ);
        CHECK_VALUE(i2c_offset, 1);
        CHECK_VALUE(rw_data->in_out_buffer.length, 257);
        CHECK_VALUE(
            rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_RAW_BYTES
        );
        CHECK_VALUE(rw_data->access_length, 255);
        break;
    case 0x23D:
        CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_READ);
        CHECK_VALUE(i2c_offset, 1);
        CHECK_VALUE(rw_data->in_out_buffer.length, 257);
        CHECK_VALUE(
            rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_RAW_PROCESS_BYTES
        );
        CHECK_VALUE(rw_data->access_length, 123);
        break;
    default:
        error("bad serial command %" PRIu64, rw_data->command);
    }

    if (op == UACPI_REGION_OP_SERIAL_WRITE) {
        uacpi_u16 value;

        memcpy(&value, rw_data->in_out_buffer.const_bytes, sizeof(value));
        CHECK_VALUE(value, rw_data->command);
    }

    response = rw_data->command + 1;
    memcpy(rw_data->in_out_buffer.bytes, &response, sizeof(response));

    uacpi_free_resource(res);
    return UACPI_STATUS_OK;
}

void test_address_spaces(void)
{
    uacpi_status st;
    uacpi_object *arg;

    arg = uacpi_object_create_integer(0);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_IPMI, ipmi_handler, NULL
    );
    ensure_ok_status(st);
    eval_one(arg, UACPI_ADDRESS_SPACE_IPMI);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_GENERAL_PURPOSE_IO,
        gpio_handler, NULL
    );
    ensure_ok_status(st);
    eval_one(arg, UACPI_ADDRESS_SPACE_GENERAL_PURPOSE_IO);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_PCC, pcc_handler, NULL
    );
    ensure_ok_status(st);
    eval_one(arg, UACPI_ADDRESS_SPACE_PCC);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_PRM, prm_handler, NULL
    );
    ensure_ok_status(st);
    eval_one(arg, UACPI_ADDRESS_SPACE_PRM);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_FFIXEDHW, ffixedhw_handler,
        NULL
    );
    ensure_ok_status(st);
    eval_one(arg, UACPI_ADDRESS_SPACE_FFIXEDHW);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_GENERIC_SERIAL_BUS,
        generic_serial_bus_handler, NULL
    );
    ensure_ok_status(st);
    eval_one(arg, UACPI_ADDRESS_SPACE_GENERIC_SERIAL_BUS);

    uacpi_object_unref(arg);
}
