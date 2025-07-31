// Name: Load/LoadTable handle bogus-sized tables correctly
// Expect: int => 0

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    External(\SSDT, IntObj)
    External(\OK, IntObj)
    External(\TYPE, IntObj)

    // All dynamic loads branch into here
    If (CondRefOf(\OK)) {
        if (TYPE == 0) {
            Local0 = Load(\SSDT)
        } Else {
            DataTableRegion (DSDT, "DSDT", "uTEST", "TESTTABL")
            Field (DSDT, DwordAcc, NoLock, Preserve) {
                SIGN, 32,
                LENG, 32,
            }

            // Make our own length bogus, then try to load ourselves, this should fail
            LENG = 3
            LoadTable("DSDT", "uTEST", "TESTTABL", "", "", 0)
        }

        // Should be unreachable, we expect the Load above to abort us
        OK += 1
        Return (0)
    }

    Name (SSDT, Buffer {
        0x53, 0x53, 0x44, 0x54, 0x2a, 0x00, 0x00, 0x00,
        0x01, 0x89, 0x75, 0x54, 0x45, 0x53, 0x54, 0x00,
        0x42, 0x41, 0x44, 0x54, 0x42, 0x4c, 0x00, 0x00,
        0xf0, 0xf0, 0xf0, 0xf0, 0x49, 0x4e, 0x54, 0x4c,
        0x28, 0x06, 0x23, 0x20, 0x70, 0x0d, 0x3f, 0x00,
        0x5b, 0x31
    })
    Name (OK, 0)
    Name (TYPE, 0)

    Method (MAIN) {
        // Make the size something bogus
        SSDT[4] = 0x11
        SSDT[5] = 0
        SSDT[6] = 0
        SSDT[7] = 0

        // Try Load'ing a bogus length SSDT
        TYPE = 0
        Local0 = LoadTable("DSDT", "uTEST", "TESTTABL", "", "", 0)

        // Now try LoadTable ourselves, after corrupting our own length
        TYPE = 1
        Local0 = LoadTable("DSDT", "uTEST", "TESTTABL", "", "", 0)

        // Expect the above to fail
        if (Local0 || OK) {
            Return (1)
        }

        Return (0)
    }
}
