// Name: State reset waits for the notifications that are in flight
// Expect: str => check-state-reset-waits-for-notifications

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-state-reset-waits-for-notifications")
    }

    Device (DEV0) {
        Name (_HID, "TEST0000")
    }

    Method (NTF0) {
        Notify (DEV0, 0x81)
    }

    Scope (\_GPE) {
        Method (_L00) {
            Notify (DEV0, 0x80)
        }
    }
}
