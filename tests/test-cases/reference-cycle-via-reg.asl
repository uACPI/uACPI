// Name: A reference cycle that is completed by _REG is rejected
// Expect: int => 0

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Device (EC0) {
        Name (_HID, EisaId ("PNP0C09"))

        OperationRegion (REG0, EmbeddedControl, 0, 0x10)
        Name (XXXX, 0)

        /*
         * The region is disconnected as it's being overwritten by a reference
         * to XXXX, see below. Make XXXX refer to the region in response:
         * neither one of those stores is a cycle by itself, but both of them
         * put together are.
         */
        Method (_REG, 2) {
            If (Arg0 == 3 && Arg1 == 0) {
                CopyObject (RefOf (REG0), XXXX)
            }
        }
    }

    /*
     * A cyclic store aborts the running method, so this is top-level code of
     * its own SSDT, which turns the error into a failed Load() instead.
     *
     * DefinitionBlock ("", "SSDT", 2, "uTEST", "CYCTBL_R", 1)
     * {
     *     External (\EC0.XXXX, IntObj)
     *     External (\EC0.REG0, OpRegionObj)
     *
     *     CopyObject (RefOf (\EC0.XXXX), \EC0.REG0)
     * }
     */
    Name (CYCR, Buffer () {
        0x53, 0x53, 0x44, 0x54, 0x57, 0x00, 0x00, 0x00,
        0x02, 0x2C, 0x75, 0x54, 0x45, 0x53, 0x54, 0x00,
        0x43, 0x59, 0x43, 0x54, 0x42, 0x4C, 0x5F, 0x52,
        0x01, 0x00, 0x00, 0x00, 0x49, 0x4E, 0x54, 0x4C,
        0x30, 0x09, 0x26, 0x20, 0xA0, 0x1C, 0x00, 0x15,
        0x5C, 0x2E, 0x45, 0x43, 0x30, 0x5F, 0x58, 0x58,
        0x58, 0x58, 0x01, 0x00, 0x15, 0x5C, 0x2E, 0x45,
        0x43, 0x30, 0x5F, 0x52, 0x45, 0x47, 0x30, 0x0A,
        0x00, 0x9D, 0x71, 0x5C, 0x2E, 0x45, 0x43, 0x30,
        0x5F, 0x58, 0x58, 0x58, 0x58, 0x5C, 0x2E, 0x45,
        0x43, 0x30, 0x5F, 0x52, 0x45, 0x47, 0x30
    })

    Method (MAIN) {
        // The store is only known to be a cycle once _REG is done
        If (Load (CYCR)) {
            Printf("A store that creates a reference cycle was not rejected")
            Return (1)
        }

        // The region is still there, it has just lost its handler
        If (ObjectType (\EC0.REG0) != 10) {
            Printf("REG0 was overwritten: %o", ObjectType (\EC0.REG0))
            Return (2)
        }

        Return (0)
    }
}
