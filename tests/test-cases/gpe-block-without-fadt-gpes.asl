// Name: A GPE block can share the SCI if the FADT has no GPE blocks
// Expect: str => check-gpe-block-works-without-fadt-gpes

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-gpe-block-works-without-fadt-gpes")
    }

    Device (GPEB) {
        Name (_HID, "ACPI0006")

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
