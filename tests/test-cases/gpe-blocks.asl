// Name: GPE blocks can be installed and uninstalled
// Expect: str => check-gpe-blocks-work

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-gpe-blocks-work")
    }

    Device (DEV0) {
        Name (_HID, "TEST0000")
    }

    // A block of 16 events
    Device (GPEB) {
        Name (_HID, "ACPI0006")

        Name (CNT0, 0)
        Name (CNT9, 0)

        Method (_L00) {
            CNT0++
            Notify (DEV0, 0x80)
        }

        Method (_E09) {
            CNT9++
        }

        // Right past the end of the block, must not be matched
        Method (_L10) { }
    }

    // A block of 8 events
    Device (GPEC) {
        Name (_HID, "ACPI0006")

        Name (CNT1, 0)
        Name (CNT3, 0)

        Method (_L01) {
            CNT1++
        }

        // Marked as a wake event by the test
        Method (_L02) { }

        Method (_E03) {
            CNT3++
        }
    }

    Scope (\_GPE) {
        Name (CNT0, 0)
        Name (CNT1, 0)

        Method (_L00) {
            CNT0++
        }

        Method (_E01) {
            CNT1++
        }
    }
}
