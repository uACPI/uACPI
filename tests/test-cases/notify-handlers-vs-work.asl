// Name: Notify handlers can be (un)installed while work is in flight
// Expect: str => check-notify-handlers-dont-deadlock

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-notify-handlers-dont-deadlock")
    }

    Device (DEV0) {
        Name (_HID, "TEST0000")
    }

    Device (DEV1) {
        Name (_HID, "TEST0001")
    }

    Method (NTF0) {
        Notify (DEV0, 0x81)
    }

    // Invoked by a notify handler of DEV0
    Method (NTF1) {
        Notify (DEV1, 0x82)
    }

    Scope (\_GPE) {
        Method (_L00) {
            Notify (DEV0, 0x80)
        }

        /*
         * GPE 01 has no method on purpose, it's configured to implicitly
         * notify DEV1 by the test.
         */
    }
}
