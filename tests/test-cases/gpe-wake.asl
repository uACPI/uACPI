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

        Name (CN12, 0)

        /*
         * DefinitionBlock ("", "SSDT", 2, "uTEST", "GPETAB12", 0xF0F0F0F0)
         * {
         *     External (\_GPE.CN12, IntObj)
         *
         *     Scope (\_GPE) {
         *         Method (_L12) {
         *             CN12++
         *         }
         *     }
         * }
         */
        Name (TB12, Buffer {
            0x53,0x53,0x44,0x54,0x47,0x00,0x00,0x00,
            0x02,0x6B,0x75,0x54,0x45,0x53,0x54,0x00,
            0x47,0x50,0x45,0x54,0x41,0x42,0x31,0x32,
            0xF0,0xF0,0xF0,0xF0,0x49,0x4E,0x54,0x4C,
            0x30,0x09,0x26,0x20,0xA0,0x0F,0x00,0x15,
            0x5C,0x2E,0x5F,0x47,0x50,0x45,0x43,0x4E,
            0x31,0x32,0x01,0x00,0x10,0x12,0x5C,0x5F,
            0x47,0x50,0x45,0x14,0x0B,0x5F,0x4C,0x31,
            0x32,0x00,0x75,0x43,0x4E,0x31,0x32
        })

        /*
         * Brings in a handler for GPE 12, which is a wake event that doesn't
         * have one either, and is called by whoever is notified because of it.
         */
        Method (LD12) {
            Load (TB12, Local0)
            Return (Local0)
        }
    }
}
