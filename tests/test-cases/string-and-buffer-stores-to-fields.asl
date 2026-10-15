// Name: Strings and Buffers are stored to fields in field-sized chunks
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

    OperationRegion (NVSM, SystemMemory, 0x100000, 0x20)
    Field (NVSM, ByteAcc, NoLock, Preserve) {
        F8, 8,
        F16, 16,
        , 2,
        F4, 4,
        Offset (4),
        F32, 32,
        F64, 64,
        IDXR, 8,
        DATR, 8,
    }
    Field (NVSM, DWordAcc, NoLock, Preserve) {
        Offset (0x10),
        F96, 96,
    }

    // The same bytes, to see what reached the region
    Field (NVSM, ByteAcc, NoLock, Preserve) {
        R8, 8,
        R16, 16,
        R4, 8,
        R32, 32,
        R64, 64,
        RIDX, 8,
        RDAT, 8,
    }
    Field (NVSM, DWordAcc, NoLock, Preserve) {
        Offset (0x10),
        R96, 96,
    }

    IndexField (IDXR, DATR, ByteAcc, NoLock, Preserve) {
        Offset (0x10),
        IFU0, 8,
    }

    Name (BUF0, Buffer (8) { 0 })
    CreateByteField (BUF0, 0, BFB)
    CreateDWordField (BUF0, 2, BFD)
    CreateField (BUF0, 50, 4, BF4)

    Name (BUF1, Buffer { 1, 2, 3 })

    Method (MAIN) {
        // NT writes every chunk, so only the last one is left
        F8 = "Hello world!"
        CHK ("String to an 8-bit field", R8, 0x21)

        F16 = "ABC"
        CHK ("String to a 16-bit field", R16, 0x43)

        R4 = 0xFF
        F4 = Buffer { 1, 2, 3 }
        CHK ("Buffer to a 4-bit field", R4, 0xCF)

        F32 = Buffer { 0x11, 0x22, 0x33, 0x44, 0x55 }
        CHK ("Buffer to a 32-bit field", R32, 0x55)

        F64 = "ABCDEFGHI"
        CHK ("String to a 64-bit field", R64, 0x49)

        F96 = Buffer {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD
        }
        CHK ("Buffer to a 96-bit field", R96,
             Buffer { 0xDD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })

        IFU0 = "XYZ"
        CHK ("Index register after a String to an index field", RIDX, 0x10)
        CHK ("Data register after a String to an index field", RDAT, 0x5A)

        // Nothing is written for an empty one
        R8 = 0x5A
        F8 = ""
        CHK ("Empty String to a field", R8, 0x5A)

        R32 = 0x12345678
        F32 = ""
        CHK ("Empty String to a 32-bit field", R32, 0x12345678)

        // An Integer is written once
        F16 = 0x332211
        CHK ("Integer to a 16-bit field", R16, 0x2211)

        BFB = "ABC"
        CHK ("String to a byte buffer field", DerefOf (BUF0[0]), 0x43)

        BFD = Buffer { 0x11, 0x22, 0x33, 0x44, 0x55 }
        CHK ("Buffer to a dword buffer field", BUF0,
             Buffer { 0x43, 0, 0x55, 0, 0, 0, 0, 0 })

        BF4 = Buffer { 1, 2, 3 }
        CHK ("Buffer to a 4-bit buffer field", BUF0,
             Buffer { 0x43, 0, 0x55, 0, 0, 0, 0x0C, 0 })

        BFB = ""
        CHK ("Empty String to a buffer field", DerefOf (BUF0[0]), 0x43)

        BFD = 0x2211
        CHK ("Integer to a dword buffer field", BUF0,
             Buffer { 0x43, 0, 0x11, 0x22, 0, 0, 0x0C, 0 })

        BUF1[1] = "ABC"
        CHK ("String to a buffer index", BUF1, Buffer { 1, 0x43, 3 })

        BUF1[1] = ""
        CHK ("Empty String to a buffer index", BUF1, Buffer { 1, 0x43, 3 })

        Return (FAIL)
    }
}
