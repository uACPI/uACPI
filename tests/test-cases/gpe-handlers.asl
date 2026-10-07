// Name: General purpose events are dispatched to their handlers
// Expect: str => check-gpe-handlers-work

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-gpe-handlers-work")
    }

    Device (DEV0) {
        Name (_HID, "TEST0000")
    }

    Scope (\_GPE) {
        Name (CNT0, 0)
        Name (CNT1, 0)
        Name (CN80, 0)
        Name (CNFF, 0)

        Method (_L00) {
            CNT0++
        }

        Method (_E01) {
            CNT1++
        }

        /*
         * The first and the last events of the second FADT block. The former
         * sits right past the end of the first one, and so must not be matched
         * against it.
         */
        Method (_L80) {
            CN80++
        }

        Method (_EFF) {
            CNFF++
        }

        // Neither of these is a valid GPE method
        Method (_LXY) { }
        Method (_Q00) { }
    }
}
