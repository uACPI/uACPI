// Name: _REG is able to access the region that it's disconnecting
// Expect: int => 0

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Device (EC0) {
        Name (_HID, EisaId ("PNP0C09"))

        OperationRegion (REG0, EmbeddedControl, 0, 0x10)
        Field (REG0, ByteAcc, NoLock, Preserve) {
            FLD0, 8,
        }

        // The number of times that the region was disconnected
        Name (DISS, 0)

        // The number of times that it was accessible while at it
        Name (ACCS, 0)

        Method (_REG, 2) {
            If (Arg0 == 3 && Arg1 == 0) {
                DISS++

                /*
                 * This is our last chance to make use of the region, as it's
                 * only taken away once we return. The method is aborted right
                 * here if that's not the case.
                 */
                FLD0 = 0xFF
                ACCS++
            }
        }
    }

    Method (MAIN) {
        // Overwriting a region is not guaranteed to disconnect it
        CopyObject (One, \EC0.REG0)

        If (_OSI ("TestRunner") && \EC0.DISS != 1) {
            Printf("REG0 was disconnected %o time(s)", \EC0.DISS)
            Return (1)
        }

        If (\EC0.ACCS != \EC0.DISS) {
            Printf("REG0 was accessible for %o out of %o disconnect(s)",
                   \EC0.ACCS, \EC0.DISS)
            Return (2)
        }

        Return (0)
    }
}
