project('uacpi', meson_version: '>=1.1', version: '3.2.0')

src = [
    'source/tables.c',
    'source/types.c',
    'source/uacpi.c',
    'source/utilities.c',
    'source/interpreter.c',
    'source/opcodes.c',
    'source/namespace.c',
    'source/stdlib.c',
    'source/shareable.c',
    'source/opregion.c',
    'source/default_handlers.c',
    'source/io.c',
    'source/notify.c',
    'source/sleep.c',
    'source/registers.c',
    'source/resources.c',
    'source/event.c',
    'source/mutex.c',
    'source/osi.c',
]

sources = files(src)
includes = include_directories('include')

if get_option('install_pkgconfig')
    install_data(sources, install_dir: get_option('datadir') / 'uacpi', preserve_path: true)
    install_subdir('include', install_dir: get_option('datadir') / 'uacpi')

    sourcelist = ''
    foreach f : src
        if sourcelist != ''
            sourcelist += ';'
        endif
        sourcelist += f
    endforeach

    import('pkgconfig').generate(
        name: 'uacpi',
        description: 'A portable and easy-to-integrate implementation of the Advanced Configuration and Power Interface (ACPI)',
        version: meson.project_version(),
        dataonly: true,
        variables: [
            'installdir=${pc_sysrootdir}/' + get_option('prefix') / get_option('datadir') / 'uacpi/',
            'includedir=${installdir}/include/',
            'sourcefiles=' + sourcelist,
        ]
    )
endif
