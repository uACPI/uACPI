# uACPI

A portable and easy-to-integrate implementation of the Advanced Configuration and Power Interface (ACPI).

[![CI](https://github.com/UltraOS/uACPI/actions/workflows/main.yml/badge.svg)](https://github.com/UltraOS/uACPI/actions/workflows/main.yml)

## Features

- A fast and well-tested AML interpreter optimized to use very little stack space
- NT-compatible on a fundamental level (see [examples](#more-detailed-overview))
- Very easy to integrate (ships with own overridable standard library implementation)
- Highly flexible and configurable (optional sized frees, reduced-hw-only mode, etc.)
- A fairly advanced event subsystem (GPE/fixed, wake, implicit notify, AML handlers)
- Table management API (search, dynamic installation/loading, overrides, etc.)
- Operation region subsystem (user handlers, support for BufferAcc opregions, builtins for common types)
- Sleep state management (transition to any S state, wake vector programming)
- PCI routing table retrieval & interrupt model API
- Device search API
- Resource subsystem supporting every resource defined by ACPI 6.6
- Interface & feature management exposed via _OSI
- Client-defined Notify() handlers
- Firmware global lock management (_GL, locked fields, public API)
- GAS read/write API
- Fully thread safe
- Supports both 32-bit and 64-bit platforms
- A special barebones mode with only table API (see [config.h](include/uacpi/platform/config.h#L127))

## Why would I use this over ACPICA?

### 1. Performance

uACPI shows a consistent speedup of about **3.5x** over ACPICA in synthetic AML tests.

<details><summary>More details</summary>

Code that was tested:
```asl
Method (TOMS, 2, NotSerialized) {
    Return ((Arg1 - Arg0) / 10000)
}

Method (ADDM, 1, NotSerialized) {
    Local0 = 0

    While (Arg0) {
        Local0 += Arg0 + Arg0
        Arg0--
    }

    Return (Local0)
}

// Record start time
Local0 = Timer

// Run 10 million additions
Local1 = ADDM(10000000)

// Make sure the answer matches expected
If (Local1 != 0x5AF31112D680) {
    Printf("Bad test result %o", Local1)
    Return (1)
}

// Record end time
Local2 = Timer

Printf("10,000,000 additions took %o ms",
       ToDecimalString(TOMS(Local0, Local2)))
```

Compile options (acpiexec and uACPI's test-runner): `-O3 -flto -march=znver4 -mtune=znver4`  
CPU: AMD Ryzen 9 9950X3D  
Raw test scores (~average over 10 runs):
- ACPICA: 16661 ms
- uACPI: 4753 ms

**Raw difference: 3.5053x**

</details>

Real hardware tests of the same operating system using uACPI vs ACPICA show
at least a **1.75-2x speedup** while measuring the time it takes to load the initial
AML namespace.

<details><summary>More details</summary>

OS: [proxima](https://github.com/proxima-os)

Compile options: `-O3 -flto`

### Test Subject 1

Specs: Gigabyte B550M S2H, AMD Ryzen 5800X, 64GB RAM  
Firmware: F19d (10097 AML opcodes)

Results:
- ACPICA: 3,936,953 ns
- uACPI: 1,902,077 ns

**Raw difference: 2.0698x**

### Test Subject 2

Specs: Toshiba Portege R30-A, Intel Core i5-4200M, 4GB RAM   
Firmware: 4.40 (4962 AML opcodes)

Results:
- ACPICA: 10,899,233 ns
- uACPI: 6,227,036 ns

**Raw difference: 1.7503x**

</details>

### 2. NT-compatible from the ground up
                              
Over the decades of development, ACPICA has accumulated a lot of workarounds for
AML expecting NT-specific behaviors, and is still missing compatibility in a lot
of critical aspects.

uACPI, on the other hand, is built to be natively NT-compatible without extra
workarounds.

Some specific highlights include:
- Reference objects, especially multi-level reference chains
- Implicit cast semantics
- Object mutability
- Named object resolution, especially for named objects inside packages
                             
### 3. Fundamental safety
             
uACPI is built to always assume the worst about the AML byte code it's executing,
and as such, has a more sophisticated object lifetime tracking system, as well
as carefully designed handling for various edge-cases, including race conditions.

Some of the standard uACPI test cases crash both ACPICA, and the NT AML 
interpreters.

While a permanent fuzzing solution for uACPI is currently WIP, it has already
been fuzzed quite extensively and all known issues have been fixed.

### 4. No recursion

Running at kernel level has a lot of very strict limitations, one of which is a
tiny stack size, which can sometimes be only a few pages in length.

Of course, both ACPICA and uACPI have non-recursive AML interpreters, but there
are still edge cases that cause potentially unbounded recursion.

One such example are the dynamic table load operators from AML
(`Load`/`LoadTable`): these cause a linear growth in stack usage per call in
ACPICA, whereas in uACPI these  are treated as special method calls,
and as such, don't increase stack usage whatsoever.

### More detailed overview
Expressions within package:
```asl
Method (TEST) {
    Local0 = 10
    Local1 = Package { Local0 * 5 }
    Return (DerefOf(Local1[0]))
}

// ACPICA: AE_SUPPORT, Expressions within package elements are not supported
// Windows, uACPI: Local0 = 50
Local0 = TEST()
```

Packages outside of a control method:
```asl
// ACPICA: internal error
// Windows, uACPI: ok
Local0 = Package { 1 }
```

Reference rebind semantics:
```asl
Local0 = 123
Local1 = RefOf(Local0)

// ACPICA: Local1 = 321, Local0 = 123
// Windows, uACPI: Local1 = reference->Local0, Local0 = 321
Local1 = 321
```

Increment/Decrement:
```asl
Local0 = 123
Local1 = RefOf(Local0)

// ACPICA: error
// Windows, uACPI: Local0 = 124
Local1++
```

Multilevel references:
```asl
Local0 = 123
Local1 = RefOf(Local0)
Local2 = RefOf(Local1)

// ACPICA: Local3 = reference->Local0
// Windows, uACPI: Local3 = 123
Local3 = DerefOf(Local2)
```

Implict-cast semantics:
```asl
Name (TEST, "BAR")

// ACPICA: TEST = "00000000004F4F46"
// Windows, uACPI: TEST = "FOO"
TEST = 0x4F4F46
```
                                
Buffer size mutability:
```asl
Name (TEST, "XXXX")
Name (VAL, "")

// ACPICA: TEST = "LONGSTRING"
// Windows, UACPI: TEST = "LONG"
TEST = "LONGSTRING"

// ACPICA: VAL = "FOO"
// Windows, UACPI: VAL = ""
VAL = "FOO"
```

Returning a reference to a local object:
```asl
Method (TEST) {
    Local0 = 123

    // Use-after-free in ACPICA, perfectly fine in uACPI
    Return (RefOf(Local0))
}

Method (FOO) {
    Name (TEST, 123)

    // Use-after-free in ACPICA, object lifetime prolonged in uACPI (node is still removed from the namespace)
    Return (RefOf(TEST))
}
```

CopyObject into self:
```asl
Method (TEST) {
    CopyObject(123, TEST)
    Return (1)
}

// Segfault in ACPICA, prints 1 in uACPI  
Debug = TEST()

// Unreachable in ACPICA, prints 123 in uACPI
Debug = TEST
```

There's even more examples, but this should be enough to demonstrate the fundamental differences in designs.

## Integrating into a kernel

### 1. Add uACPI sources & include directories into your project

#### If you're using CMake
Simply add the following lines to your cmake:
```cmake
include(uacpi/uacpi.cmake)

target_sources(
    my-kernel
    PRIVATE
    ${UACPI_SOURCES}
)

target_include_directories(
    my-kernel
    PRIVATE
    ${UACPI_INCLUDES}
)
```

#### If you're using Meson
Add the following lines to your meson.build:
```meson
uacpi = subproject('uacpi')

uacpi_sources = uacpi.get_variable('sources')
my_kernel_sources += uacpi_sources

uacpi_includes = uacpi.get_variable('includes')
my_kernel_includes += uacpi_includes
```

#### Any other build system
- Add all .c files from [source](source) into your target sources
- Add [include](include) into your target include directories

### 2. Implement/override platform-specific headers

uACPI defines all platform/architecture-specific functionality in a few headers inside [include/uacpi/platform](include/uacpi/platform)

All of the headers can be "implemented" by your project in a few ways:
- Implement the expected helpers exposed by the headers
- Replace the expected helpers by your own and override uACPI to use them by defining the respective `UACPI_OVERRIDE_X` variable.
In this case, the header becomes a proxy that includes a corresponding `uacpi_x.h` header exported by your project.

Currently used platform-specific headers are:
- [arch_helpers.h](include/uacpi/platform/arch_helpers.h) - defines architecture/cpu-specific helpers & thread-id-related interfaces
- [compiler.h](include/uacpi/platform/compiler.h) - defines compiler-specific helpers like attributes and intrinsics.
This already works for MSVC, clang & GCC so you most likely won't have to override it.
- [atomic.h](include/uacpi/platform/atomic.h) - defines compiler-specific helpers for dealing with atomic operations.
  Same as the header above, this should work out of the box for MSVC, clang & GCC.
- [libc.h](include/uacpi/platform/libc.h) - an empty header by default, but may be overriden by your project
if it implements any of the libc functions used by uACPI (by default uACPI uses its
own implementations to be platform-independent and to make porting easier). The
internal implementation is just the bare minimum and not optimized in any way.
- [types.h](include/uacpi/platform/types.h) - typedefs a bunch of uacpi-specific types using the `stdint.h` header. You don't have to override this
unless you don't provide `stdint.h`.
- [config.h](include/uacpi/platform/config.h) - various compile-time options and settings, preconfigured to reasonable defaults.

### 3. Implement kernel API

uACPI relies on kernel-specific API to do things like mapping/unmapping memory, writing/reading to/from IO, PCI config space, and many more things.

This API is declared in [kernel_api.h](include/uacpi/kernel_api.h) and is implemented by your kernel.

### 4. Initialize uACPI

That's it, uACPI is now integrated into your project.

You should proceed to initialization.  
Refer to the [uACPI page](https://wiki.osdev.org/uACPI) on osdev wiki to see a
snippet for basic initialization, as well as some code examples of how you may 
want to use certain APIs.

All of the headers and APIs defined in [uacpi](include/uacpi/) are public and may be utilized by your project.  
Anything inside [uacpi/internal](include/uacpi/internal) is considered private/undocumented and unstable API.

## Developing and contributing

Most development work is fully doable in userland using the test runner.

### Setting up an IDE:

Simply open [tests/runner/CMakeLists.txt](tests/runner/CMakeLists.txt) in your favorite IDE.

For Visual Studio:
```
cd tests\runner && mkdir build && cd build && cmake ..
```

Then just simply open the .sln file generated by cmake.

### Running the test suite:
```
./tests/run_tests.py
```

If you want to contribute:
- Commits are expected to be atomic (changing one specific thing, or introducing one feature) with detailed description (if one is warranted for), an S-o-b line is welcome
- Code style is 4-space tabs, 80 cols, the rest can be seen by just looking at the current code

**All contributions are very welcome!**

## Notable projects using uACPI & performance leaderboards

|  Project | Description | (qemu w/ Q35 + KVM) ops/s  | CPU |
|---  |--- |--- |--- |
| [proxima](https://github.com/proxima-os/) | Unix-like microkernel-based operating system with uACPI running in userspace | 10,454,158 | AMD Ryzen 9 9950X3D |
| [ilobilix](https://github.com/ilobilo/ilobilix) | Yet another monolithic Linux clone wannabe. Currently under a rewrite | 8,703,286 | AMD Ryzen 9 9950X3D |
| [Crescent2](https://github.com/Qwinci/crescent2) | An NT driver compatible kernel and userspace | 6,818,418 | Intel Core i5-13600K |
| [davix](https://github.com/dbstream/davix) | Yet another unix-like by some bored nerd | 6,364,623 | Intel Core i7-13700K |
| [Ironclad](https://ironclad-os.org) | Formally verified, hard real-time capable kernel written in SPARK and Ada | 6,196,937 | Intel Core i9-13900KS |
| [Managarm](https://github.com/managarm/managarm)  | Pragmatic microkernel-based OS with fully asynchronous I/O | 5,618,646 | Intel Core i7-14700K |
| [ChronOS](https://github.com/BUGO07/chronos) | Another basic hobby os held together by duct tape, made in rust | 5,416,703 | Intel Core Ultra 7 265KF |
| [pmOS](https://gitlab.com/mishakov/pmos) | Microkernel-based operating system written from scratch with uACPI running in userspace | 5,354,445 | AMD Ryzen 9 5900X |
| [menix](https://github.com/menix-os/menix) | A minimal and expandable Unix-like operating system | 5,239,043 | Intel Core Ultra 7 265KF |
| [Orange](https://github.com/cpplover0/orange) | Unix-like x86_64 OS with some microkernel features | 4,204,053 | AMD Ryzen 5 3600 |
| [Astral](https://github.com/mathewnd/astral) | Operating system written in C which aims be POSIX-compliant | 4,189,189 | Intel Core i5-13600K |
| [Keyronex](https://github.com/Keyronex/Keyronex) | Layered kernel with fundamentally asynchronous I/O and working set model-based memory management | 4,013,691 | AMD Ryzen 5800X |
| [Orange](https://github.com/cppLover0/Orange) | x86_64 Unix-like OS | 2,377,330 | AMD Ryzen 5 3600 |
| [OBOS](https://github.com/OBOS-dev/obos) | Hybrid Kernel with advanced driver loading | 2,141,179 | Intel Core i5-13600K |
| [NyauxKC](https://github.com/rayanmargham/NyauxKC) | Monolithic UNIX-like multi-architecture kernel | 1,966,580 | Intel Core i7-13700K |
| [ElysiumOS](https://github.com/imwux/elysium-os) | Hybrid Unix-like kernel | 1,737,654 | AMD Ryzen 7 5800X3D |
| [imaginarium](https://github.com/Khitiara/imaginarium) | Ziggy osdev experiments inspired by the NT kernel (using the zig general purpose allocator) | 1,504,436 | AMD Ryzen 7 3700X |
| [BadgerOS](https://github.com/badgeteam/BadgerOS) | A monolithic lightweight UNIX clone | 1,018,518 | AMD Ryzen 5 3600 |
| [Retro Rocket](https://github.com/brainboxdotcc/retro-rocket) | A BASIC _powered_ 64-bit SMP multitasking OS | 441,329 | Intel Xeon E5-2680 |
| [Hyra](https://github.com/sigsegv7/Hyra) | Monolithic UNIX-like OS by [OSMORA.ORG](https://osmora.org) | 199,873 | Intel Core i3-3220 |

## License

<a href="https://opensource.org/licenses/MIT">
  <img align="right" height="96" alt="MIT License" src="https://branding.cute.engineering/licenses/mit.svg" />
</a>

uACPI is licensed under the **MIT License**.  
The full license text is provided in the [LICENSE](LICENSE) file inside the root directory.
