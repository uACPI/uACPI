// Name: General purpose events can be used for wake
// Expect: str => check-wake-gpes-work

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-wake-gpes-work")
    }

    Device (DEV0) {
        Name (_HID, "TEST0000")
    }

    Device (DEV1) {
        Name (_HID, "TEST0001")
    }

    Device (DEV2) {
        Name (_HID, "TEST0002")
    }

    Scope (\_GPE) {
        Name (CNT0, 0)
        Name (CNT3, 0)

        // A regular runtime event
        Method (_L00) {
            CNT0++
        }

        // A wake event that has a handler, which is expected to do the notify
        Method (_L03) {
            CNT3++
            Notify (DEV0, 0x02)
        }

        /*
         * GPEs 10 and 11 are wake events that don't have a handler, the
         * respective devices are notified implicitly.
         */
    }
}
