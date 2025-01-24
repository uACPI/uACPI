#include <iostream>
#include <string>
#include <cstring>
#include <string_view>
#include <vector>

#include "helpers.h"
#include <uacpi/utilities.h>
#include <uacpi/resources.h>
#include <uacpi/opregion.h>
#include <uacpi/event.h>

void test_object_api()
{
    uacpi_status st;
    uacpi_object_array arr;
    uacpi_object* objects[2];
    uacpi_u64 ret;

    arr.objects = objects;
    arr.count = sizeof(objects) / sizeof(*objects);
    objects[0] = uacpi_object_create_integer(1);

    auto check_ok = [&] {
        st = uacpi_eval_integer(UACPI_NULL, "CHEK", &arr, &ret);
        ensure_ok_status(st);
        if (!ret)
            throw std::runtime_error("integer check failed");
        uacpi_object_unref(objects[1]);
    };

    st = uacpi_object_create_integer_safe(
        0xDEADBEEFDEADBEEF, UACPI_OVERFLOW_DISALLOW, &objects[1]
    );
    if (st != UACPI_STATUS_INVALID_ARGUMENT)
        throw std::runtime_error("expected integer creation to fail");

    objects[1] = uacpi_object_create_integer(0xDEADBEEF);
    check_ok();

    st = uacpi_object_assign_integer(objects[0], 2);
    ensure_ok_status(st);

    objects[1] = uacpi_object_create_cstring("Hello World");
    uacpi_object_ref(objects[1]);
    check_ok();

    uacpi_data_view view;
    view.const_text = "Hello World";
    // Don't include the null byte to check if this is accounted for
    view.length = 11;

    uacpi_object_assign_string(objects[1], view);
    check_ok();

    st = uacpi_object_assign_integer(objects[0], 3);
    ensure_ok_status(st);
    auto *tmp = uacpi_object_create_cstring("XXXX");
    objects[1] = uacpi_object_create_reference(tmp);
    uacpi_object_unref(tmp);
    check_ok();

    st = uacpi_object_assign_integer(objects[0], 4);
    ensure_ok_status(st);
    uint8_t buffer[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    view.const_bytes = buffer;
    view.length = sizeof(buffer);
    objects[1] = uacpi_object_create_buffer(view);
    check_ok();

    st = uacpi_object_assign_integer(objects[0], 5);
    ensure_ok_status(st);
    uacpi_object *pkg[3];

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

    uacpi_object_array arr1;
    arr1.objects = pkg;
    arr1.count = 3;
    objects[1] = uacpi_object_create_package(arr1);
    uacpi_object_assign_package(objects[1], arr1);
    check_ok();
    uacpi_object_unref(pkg[0]);
    uacpi_object_unref(pkg[1]);
    uacpi_object_unref(pkg[2]);

    uacpi_object_unref(objects[0]);
}

#define CHECK_VALUE(x, y)                                      \
    if ((x) != (y))                                            \
        throw std::runtime_error(                              \
            "check at " + std::to_string(__LINE__) + " failed" \
        );

void test_address_spaces()
{
    uacpi_status st;

    auto *arg = uacpi_object_create_integer(0);
    auto guard = ScopeGuard{ [=] { uacpi_object_unref(arg); } };

    auto eval_one = [&arg] (uacpi_address_space type) {
        uacpi_object_array arr = { &arg, 1 };
        uacpi_u64 out_value;

        auto st = uacpi_object_assign_integer(arg, type);
        ensure_ok_status(st);
        st = uacpi_eval_integer(nullptr, "CHEK", &arr, &out_value);
        ensure_ok_status(st);

        if (!out_value) {
            throw std::runtime_error(
                std::string(uacpi_address_space_to_string(type)) + "test failed"
            );
        }
    };

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_IPMI,
        [](uacpi_region_op op, uacpi_handle op_data) {
            if (op == UACPI_REGION_OP_ATTACH || op == UACPI_REGION_OP_DETACH)
                return UACPI_STATUS_OK;
            CHECK_VALUE(op, UACPI_REGION_OP_IPMI_COMMAND);

            auto *ipmi = reinterpret_cast<uacpi_region_ipmi_rw_data*>(op_data);
            CHECK_VALUE(ipmi->in_out_message.length, 66);

            uint64_t response;

            auto view = std::string_view(ipmi->in_out_message.const_text);
            if (view == "IPMICommandDEADBEE0") {
                response = 0xDEADBEE0;
            } else if (view == "IPMICommandDEADBEEF") {
                response = 0xDEADBEEF;
            } else {
                throw std::runtime_error(
                    "invalid IPMI command " + std::string(view)
                );
            }

            CHECK_VALUE(ipmi->command, response);

            memcpy(ipmi->in_out_message.data, &response, sizeof(response));
            return UACPI_STATUS_OK;
        }, nullptr
    );
    ensure_ok_status(st);
    eval_one(UACPI_ADDRESS_SPACE_IPMI);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_GENERAL_PURPOSE_IO,
        [](uacpi_region_op op, uacpi_handle op_data) {
            switch (op) {
            case UACPI_REGION_OP_ATTACH: {
                auto *att_data = reinterpret_cast<uacpi_region_attach_data*>(op_data);

                CHECK_VALUE(att_data->gpio_info.num_pins, 6);
                att_data->out_region_context = new uint64_t(0);
                return UACPI_STATUS_OK;
            }
            case UACPI_REGION_OP_DETACH: {
                auto *det_data = reinterpret_cast<uacpi_region_detach_data*>(op_data);
                delete reinterpret_cast<uint64_t*>(det_data->region_context);
                return UACPI_STATUS_OK;
            }
            default:
                break;
            }

            auto *rw_data = reinterpret_cast<uacpi_region_gpio_rw_data*>(op_data);
            uacpi_resource *res;

            auto ret = uacpi_get_resource_from_buffer(rw_data->connection, &res);
            ensure_ok_status(ret);
            auto g = ScopeGuard{ [res] { uacpi_free_resource(res); } };

            CHECK_VALUE(res->type, UACPI_RESOURCE_TYPE_GPIO_CONNECTION);
            auto *gpio = &res->gpio_connection;

            uacpi_namespace_node *gpio_node;

            ret = uacpi_namespace_node_find(nullptr, gpio->source.string, &gpio_node);
            ensure_ok_status(ret);

            uacpi_u64 bit_offset;
            ret = uacpi_eval_simple_integer(gpio_node, "_UID", &bit_offset);
            ensure_ok_status(ret);

            bit_offset *= 16;
            auto *state = reinterpret_cast<uint64_t*>(rw_data->region_context);

            if (rw_data->num_pins == 0 || rw_data->num_pins > 3) {
                throw std::runtime_error(
                    "bogus number of pins " + std::to_string(rw_data->num_pins)
                );
            }

            if (op == UACPI_REGION_OP_GPIO_READ)
                rw_data->value = 0;

            for (uint64_t i = 0; i < rw_data->num_pins; ++i) {
                auto abs_pin = i + rw_data->pin_offset;
                bool value;

                if (op == UACPI_REGION_OP_GPIO_READ) {
                    value = (*state >> bit_offset) & (1ull << abs_pin);

                    if (value)
                        rw_data->value |= (1ull << i);
                } else {
                    CHECK_VALUE(op, UACPI_REGION_OP_GPIO_WRITE);

                    auto mask = 1ull << abs_pin;

                    value = rw_data->value & (1ull << i);

                    if (value)
                        *state |= mask;
                    else
                        *state &= ~mask;
                }
            }

            return UACPI_STATUS_OK;
        }, nullptr
    );
    ensure_ok_status(st);
    eval_one(UACPI_ADDRESS_SPACE_GENERAL_PURPOSE_IO);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_PCC,
        [](uacpi_region_op op, uacpi_handle op_data) {
            if (op == UACPI_REGION_OP_ATTACH) {
                auto *att_data = reinterpret_cast<uacpi_region_attach_data*>(op_data);

                CHECK_VALUE(att_data->pcc_info.buffer.length, 0xFF);
                CHECK_VALUE(att_data->pcc_info.subspace_id, 0xCA)

                att_data->out_region_context = att_data->pcc_info.buffer.data;
                return UACPI_STATUS_OK;
            }

            if (op == UACPI_REGION_OP_DETACH)
                return UACPI_STATUS_OK;
            CHECK_VALUE(op, UACPI_REGION_OP_PCC_SEND);

            auto *rw_data = reinterpret_cast<uacpi_region_pcc_send_data*>(op_data);
            CHECK_VALUE(rw_data->buffer.data, rw_data->region_context);
            CHECK_VALUE(std::string_view(rw_data->buffer.const_text), "HELLO");

            uint32_t x;
            memcpy(&x, rw_data->buffer.bytes + 12, sizeof(x));
            CHECK_VALUE(x, 0xDEADBEEF);

            x = 0xBEEFDEAD;
            memcpy(rw_data->buffer.bytes + 12, &x, sizeof(x));

            return UACPI_STATUS_OK;
        }, nullptr
    );
    ensure_ok_status(st);
    eval_one(UACPI_ADDRESS_SPACE_PCC);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_PRM,
        [](uacpi_region_op op, uacpi_handle op_data) {
            if (op == UACPI_REGION_OP_ATTACH || op == UACPI_REGION_OP_DETACH)
                return UACPI_STATUS_OK;
            CHECK_VALUE(op, UACPI_REGION_OP_PRM_COMMAND);

            auto *rw_data = reinterpret_cast<uacpi_region_prm_rw_data*>(op_data);
            CHECK_VALUE(rw_data->in_out_message.length, 26);
            CHECK_VALUE(
                std::string_view(rw_data->in_out_message.const_text),
                "helloworld"
            );

            auto response = std::string_view("goodbyeworld");
            memcpy(
                rw_data->in_out_message.text, response.data(),
                response.size() + 1
            );

            return UACPI_STATUS_OK;
        }, nullptr
    );
    ensure_ok_status(st);
    eval_one(UACPI_ADDRESS_SPACE_PRM);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_FFIXEDHW,
        [](uacpi_region_op op, uacpi_handle op_data) {
            if (op == UACPI_REGION_OP_ATTACH) {
                auto *att_data = reinterpret_cast<uacpi_region_attach_data*>(op_data);
                CHECK_VALUE(att_data->generic_info.base, 0xCAFEBABE);
                CHECK_VALUE(att_data->generic_info.length, 0xFEFECACA)
                    return UACPI_STATUS_OK;
            }

            if (op == UACPI_REGION_OP_DETACH)
                return UACPI_STATUS_OK;
            CHECK_VALUE(op, UACPI_REGION_OP_FFIXEDHW_COMMAND);

            auto *rw_data = reinterpret_cast<uacpi_region_ffixedhw_rw_data*>(op_data);
            CHECK_VALUE(rw_data->in_out_message.length, 256);
            CHECK_VALUE(
                std::string_view(rw_data->in_out_message.const_text),
                "someguidandstuff"
            );

            auto response = std::string_view("ok");
            memcpy(
                rw_data->in_out_message.text, response.data(),
                response.size() + 1
            );

            return UACPI_STATUS_OK;
        }, nullptr
    );
    ensure_ok_status(st);
    eval_one(UACPI_ADDRESS_SPACE_FFIXEDHW);

    st = uacpi_install_address_space_handler(
        uacpi_namespace_root(), UACPI_ADDRESS_SPACE_GENERIC_SERIAL_BUS,
        [](uacpi_region_op op, uacpi_handle op_data) {
            if (op == UACPI_REGION_OP_ATTACH || op == UACPI_REGION_OP_DETACH)
                return UACPI_STATUS_OK;
            CHECK_VALUE(true, (op == UACPI_REGION_OP_SERIAL_READ ||
                               op == UACPI_REGION_OP_SERIAL_WRITE));

            auto *rw_data = reinterpret_cast<uacpi_region_serial_rw_data*>(op_data);
            uacpi_resource *res;

            auto ret = uacpi_get_resource_from_buffer(rw_data->connection, &res);
            ensure_ok_status(ret);
            auto g = ScopeGuard{ [res] { uacpi_free_resource(res); } };

            CHECK_VALUE(res->type, UACPI_RESOURCE_TYPE_SERIAL_I2C_CONNECTION);
            auto *gpio = &res->i2c_connection;

            uacpi_namespace_node *i2c_node;

            ret = uacpi_namespace_node_find(nullptr, gpio->common.source.string, &i2c_node);
            ensure_ok_status(ret);

            uacpi_u64 i2c_offset;
            ret = uacpi_eval_simple_integer(i2c_node, "_UID", &i2c_offset);
            ensure_ok_status(ret);

            switch (rw_data->command) {
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
                CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_SEND_RECEIVE);
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
                CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_PROCESS_CALL);
                break;
            case 0x229:
                CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_READ);
                CHECK_VALUE(i2c_offset, 0);
                CHECK_VALUE(rw_data->in_out_buffer.length, 257);
                CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_BLOCK_PROCESS_CALL);
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
                CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_RAW_BYTES);
                CHECK_VALUE(rw_data->access_length, 255);
                break;
            case 0x23D:
                CHECK_VALUE(op, UACPI_REGION_OP_SERIAL_READ);
                CHECK_VALUE(i2c_offset, 1);
                CHECK_VALUE(rw_data->in_out_buffer.length, 257);
                CHECK_VALUE(rw_data->access_attribute, UACPI_ACCESS_ATTRIBUTE_RAW_PROCESS_BYTES);
                CHECK_VALUE(rw_data->access_length, 123);
                break;
            default:
                throw std::runtime_error(
                    "bad serial command " + std::to_string(rw_data->command)
                );
            }

            if (op == UACPI_REGION_OP_SERIAL_WRITE) {
                uacpi_u16 value;
                memcpy(&value, rw_data->in_out_buffer.const_bytes, sizeof(value));
                CHECK_VALUE(value, rw_data->command);
            }

            uacpi_u16 response = rw_data->command + 1;
            memcpy(rw_data->in_out_buffer.bytes, &response, sizeof(response));

            return UACPI_STATUS_OK;
        }, nullptr
    );
    ensure_ok_status(st);
    eval_one(UACPI_ADDRESS_SPACE_GENERIC_SERIAL_BUS);
}
