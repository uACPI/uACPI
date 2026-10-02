// Name: Duplicate fields within the same field list are skipped
// Expect: int => 1

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    OperationRegion (TEST, SystemMemory, 0x100000, 128)
    Field (TEST, AnyAcc, NoLock, Preserve) {
        FILD, 1,
        FILD, 2,
        FILD, 3,
        FILD, 4,
        FOO,  5,
        BAR,  1,
        BAZ,  2,
        FILD, 3,
        FILD, 4,
        OK,   5,
    }
    Field (TEST, DWordAcc, NoLock, Preserve) {
        RAW, 32,
    }

    Name (MDUP, 0)

    // Not allowed outside of table load, this should abort
    Method (DUPS, 0, Serialized) {
        Field (TEST, AnyAcc, NoLock, Preserve) {
            MFLD, 1,
            MFLD, 1,
        }

        MDUP = 1
    }
    DUPS()

    Method (MAIN) {
        If (MDUP) {
            Printf ("Duplicate fields were created inside a method")
            Return (0)
        }

        // Only the first FILD (1 bit at offset 0) must exist
        FILD = 0xF
        FOO = 0x1F
        BAR = 1
        BAZ = 3
        OK = 0x1F

        If (RAW != 0x3E03FC01) {
            Printf ("Bad field layout: %o", ToHexString(RAW))
            Return (0)
        }

        Return (1)
    }
}
