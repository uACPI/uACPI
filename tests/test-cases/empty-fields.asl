// Name: Fields declared with a length of 0 are never accessed
// Expect: int => 0

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Name (FAIL, 0)

    Method (CHK, 3) {
        If (Arg1 != Arg2) {
            Printf ("%o: expected %o, got %o", Arg0,
                    ToHexString(Arg2), ToHexString(Arg1))
            FAIL++
        }
    }

    OperationRegion (NVSM, SystemMemory, 0x100000, 0x10)
    Field (NVSM, ByteAcc, NoLock, Preserve) {
        FZ0, 0,
        F8A, 8,
        , 3,
        FZ1, 0,
        F5B, 5,
        Offset (8),
        IDXR, 8,
        DATR, 8,
    }

    // The same bytes, to see what reached the region
    Field (NVSM, ByteAcc, NoLock, Preserve) {
        RAW0, 8,
        RAW1, 8,
        Offset (8),
        RIDX, 8,
        RDAT, 8,
    }

    IndexField (IDXR, DATR, ByteAcc, NoLock, Preserve) {
        Offset (0x10),
        IZ0, 0,
        I8, 8,
    }

    Method (MAIN) {
        // Empty fields don't take up any room
        F8A = 0x5A
        CHK ("Field after an empty one at offset 0", RAW0, 0x5A)

        RAW1 = 0
        F5B = 0x1F
        CHK ("Field after an empty one at bit 3", RAW1, 0xF8)

        CHK ("Read from an empty field", FZ0, 0)
        CHK ("Read from an empty field at bit 3", FZ1, 0)

        FZ0 = 0x12345678
        FZ0 = "Hello"
        FZ0 = Buffer { 0x11, 0x22, 0x33 }
        FZ1 = 0xFF
        CHK ("Byte under empty fields after writes to them", RAW0, 0x5A)
        CHK ("Byte under an empty field at bit 3 after a write to it",
             RAW1, 0xF8)

        // Not even the index register is written for an empty index field
        RIDX = 0x42
        IZ0 = 0x77
        CHK ("Index register after a write to an empty index field",
             RIDX, 0x42)

        Local0 = IZ0
        CHK ("Read from an empty index field", Local0, 0)
        CHK ("Index register after a read from an empty index field",
             RIDX, 0x42)

        I8 = 0x66
        CHK ("Index register after a write to the next index field",
             RIDX, 0x10)

        Return (FAIL)
    }
}
