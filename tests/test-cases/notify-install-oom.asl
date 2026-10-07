// Name: Notify handler installation recovers from a failed allocation
// Expect: str => check-notify-install-handles-oom

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-notify-install-handles-oom")
    }

    Device (DEV0) {
        Name (_HID, "TEST0000")
    }

    Method (NTF0) {
        Notify (DEV0, 0x80)
    }
}
