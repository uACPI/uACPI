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

    Device (EC1) {
        Name (_HID, EisaId ("PNP0C09"))

        OperationRegion (REG1, EmbeddedControl, 0, 0x10)
        Field (REG1, ByteAcc, NoLock, Preserve) {
            FLD1, 8,
        }

        // The number of times that the region was connected & disconnected
        Name (CONS, 0)
        Name (DISS, 0)

        /*
         * Gets rid of the region as soon as it's disconnected, which is what
         * happens when someone else gets rid of it.
         */
        Method (_REG, 2) {
            If (Arg1 == 1) {
                CONS++
            } Else {
                DISS++
                CopyObject (Zero, REG1)
            }
        }
    }

    Method (MAIN) {
        /*
         * Both of the regions were connected by the time we got here, and the
         * first one is long gone as a result. It's not unheard of for _REG of
         * an embedded controller to be executed once more at that point, as
         * it's now a device that has no regions at all.
         */
        If (\EC0.CONS == 0 || (_OSI ("TestRunner") && \EC0.CONS != 1)) {
            Printf("REG0 was connected %o time(s)", \EC0.CONS)
            Return (1)
        }

        If (ObjectType (\EC0.REG0) != 1) {
            Printf("REG0 was not overwritten: %o", ObjectType (\EC0.REG0))
            Return (2)
        }

        If (\EC1.CONS != 1 || \EC1.DISS != 0) {
            Printf("REG1 was connected %o time(s) and disconnected %o time(s)",
                   \EC1.CONS, \EC1.DISS)
            Return (3)
        }

        /*
         * Overwriting a region is not guaranteed to disconnect it. If it does,
         * the region is detached from its handler, and _REG is executed, which
         * overwrites the region as well. This must not result in any of that
         * being done all over again.
         */
        Local0 = \EC1.FLD1
        CopyObject (One, \EC1.REG1)

        If (\EC1.DISS > 1 || (_OSI ("TestRunner") && \EC1.DISS != 1)) {
            Printf("REG1 was disconnected %o time(s)", \EC1.DISS)
            Return (4)
        }

        If (\EC1.REG1 != One) {
            Printf("REG1 was not overwritten: %o", \EC1.REG1)
            Return (5)
        }

        Return (0)
    }
}
