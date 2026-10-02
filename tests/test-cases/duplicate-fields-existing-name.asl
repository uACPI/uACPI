// Name: Fields with already existing names are skipped
// Expect: int => 1

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Name (FILD, 0xCAFE)

    OperationRegion (TEST, SystemMemory, 0x100000, 128)
    Field (TEST, AnyAcc, NoLock, Preserve) {
        FOO,  4,
        FILD, 4,
        BAR,  8,
    }
    Field (TEST, AnyAcc, NoLock, Preserve) {
        Offset (2),
        BAZ,  4,
        FOO,  8,
        OK,   4,
    }
    Field (TEST, DWordAcc, NoLock, Preserve) {
        RAW, 32,
    }

    Method (MAIN) {
        If (ObjectType(FILD) != 1 || FILD != 0xCAFE) {
            Printf ("FILD was overwritten: %o", FILD)
            Return (0)
        }

        // Only the first FOO (4 bits at offset 0) must exist
        FOO = 0xFF
        BAR = 0xAA
        BAZ = 0x5
        OK = 0xC

        If (RAW != 0xC005AA0F) {
            Printf ("Bad field layout: %o", ToHexString(RAW))
            Return (0)
        }

        Return (1)
    }
}
