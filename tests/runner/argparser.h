#pragma once

#include "helpers.h"
#include <stdbool.h>
#include <string.h>

typedef enum {
    ARG_FLAG,
    ARG_PARAM,
    ARG_LIST,
    ARG_HELP,
    ARG_POSITIONAL,
} arg_type_t;

typedef struct {
    const char *as_full;
    char as_short;
    arg_type_t type;
    const char *description;
    bool is_optional;
    bool parsed;
    vector_t values;
} arg_spec_t;

#define ARG_POS(name, desc)     \
    {                           \
        .as_full = name,        \
        .type = ARG_POSITIONAL, \
        .description = desc,    \
    }
#define ARG_LIST(name, short, desc) \
    {                               \
        .as_full = name,            \
        .as_short = short,          \
        .type = ARG_LIST,           \
        .description = desc,        \
        .is_optional = true,        \
    }
#define ARG_FLAG(name, short, desc) \
    {                               \
        .as_full = name,            \
        .as_short = short,          \
        .type = ARG_FLAG,           \
        .description = desc,        \
        .is_optional = true,        \
    }
#define ARG_PARAM(name, short, desc) \
    {                                \
        .as_full = name,             \
        .as_short = short,           \
        .type = ARG_PARAM,           \
        .description = desc,         \
        .is_optional = true,         \
    }
#define ARG_HELP(name, short, desc) \
    {                               \
        .as_full = name,            \
        .as_short = short,          \
        .type = ARG_HELP,           \
        .description = desc,        \
        .is_optional = true,        \
    }

typedef struct {
    arg_spec_t *const *positional_args;
    size_t num_positional_args;
    arg_spec_t *const *option_args;
    size_t num_option_args;
} arg_parser_t;

static inline void print_help(const arg_parser_t *parser)
{
    size_t i;

    printf("uACPI test runner:\n");

    for (i = 0; i < parser->num_positional_args; i++)
        printf(
            "           [%s] %s\n", parser->positional_args[i]->as_full,
            parser->positional_args[i]->description
        );

    for (i = 0; i < parser->num_option_args; i++)
        printf(
            "%s [--%s/-%c] %s\n",
            parser->option_args[i]->is_optional ? "(optional)" : "          ",
            parser->option_args[i]->as_full,
            parser->option_args[i]->as_short,
            parser->option_args[i]->description
        );
}

static inline bool is_arg(const char *arg)
{
    size_t length = strlen(arg);

    switch (length) {
    case 0:
    case 1:
        return false;
    case 2:
        return arg[0] == '-';
    default:
        return arg[0] == '-' && arg[1] == '-';
    }
}

static inline void parse_args(
    const arg_parser_t *parser, int argc, char *argv[]
)
{
    size_t num_args = argc;
    arg_spec_t *active_spec = NULL;
    size_t arg_index;

    if (num_args < 2) {
        print_help(parser);
        exit(1);
    }

    if (parser->num_positional_args) {
        if ((num_args - 1) < parser->num_positional_args)
            error(
                "expected at least %zu positional arguments",
                parser->num_positional_args
            );

        for (arg_index = 0; arg_index < parser->num_positional_args;
             ++arg_index)
            vector_add(
                &parser->positional_args[arg_index]->values,
                argv[1 + arg_index], 0
            );
    }

    for (arg_index = 1 + parser->num_positional_args; arg_index < num_args;
         ++arg_index) {
        char *current_arg = argv[arg_index];
        bool is_new_arg = is_arg(current_arg);
        arg_spec_t *new_spec = NULL;
        size_t length;

        if (active_spec) {
            if (!is_new_arg) {
                if (active_spec->type == ARG_FLAG)
                    error("unexpected argument %s", current_arg);

                if (active_spec->type == ARG_PARAM &&
                    active_spec->values.count == 1)
                    error("too many arguments for %s", active_spec->as_full);

                vector_add(&active_spec->values, current_arg, 0);
                continue;
            }

            if ((active_spec->type == ARG_PARAM ||
                active_spec->type == ARG_LIST) &&
                active_spec->values.count == 0)
                error("expected an argument for %s", active_spec->as_full);
        }

        length = strlen(current_arg);

        if (length >= 2) {
            size_t i;

            for (i = 0; i < parser->num_option_args; i++) {
                arg_spec_t *spec = parser->option_args[i];

                if (length == 2 && spec->as_short == current_arg[1]) {
                    new_spec = spec;
                    break;
                } else if (strcmp(spec->as_full, &current_arg[2]) == 0) {
                    new_spec = spec;
                    break;
                }
            }
        }

        if (new_spec == NULL)
            error("unexpected argument %s", current_arg);

        active_spec = new_spec;
        if (active_spec->type == ARG_HELP) {
            print_help(parser);
            exit(1);
        }

        active_spec->parsed = true;
    }
}

static inline bool is_set(const arg_spec_t *spec)
{
    return spec->parsed;
}

static inline const char *get(const arg_spec_t *spec)
{
    if (spec->values.count == 0)
        error("no argument provided for %s", spec->as_full);

    return spec->values.blobs[0].data;
}

static inline uint64_t get_uint(const arg_spec_t *spec)
{
    return strtoull(get(spec), NULL, 10);
}

static inline uint64_t get_uint_or(
    const arg_spec_t *spec, uint64_t default_value
)
{
    if (is_set(spec))
        return get_uint(spec);

    return default_value;
}
