// Name: _REG is allowed to overwrite the region that it's called for
// Expect: int => 0

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Device (EC0) {
        Name (_HID, EisaId ("PNP0C09"))

        OperationRegion (REG0, EmbeddedControl, 0, 0x10)

        // The number of times that the region was connected
        Name (CONS, 0)

        // Gets rid of the region as soon as it's connected
        Method (_REG, 2) {
            If (Arg1 == 1) {
                CONS++
                CopyObject (Zero, REG0)
            }
        }
    }

    Method (MAIN) {
        /*
         * The region was connected by the time we got here, and is long gone
         * as a result. It's not unheard of for _REG of an embedded controller
         * to be executed once more at that point, as it's now a device that
         * has no regions at all.
         */
        If (\EC0.CONS == 0 || (_OSI ("TestRunner") && \EC0.CONS != 1)) {
            Printf("REG0 was connected %o time(s)", \EC0.CONS)
            Return (1)
        }

        If (ObjectType (\EC0.REG0) != 1) {
            Printf("REG0 was not overwritten: %o", ObjectType (\EC0.REG0))
            Return (2)
        }

        Return (0)
    }
}
