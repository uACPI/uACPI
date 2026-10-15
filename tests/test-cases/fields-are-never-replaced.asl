// Name: Fields are always written to, never replaced
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
        FLD0, 8,
        IDXR, 8,
        DATR, 8,
        BNKR, 8,
        BDAT, 8,
    }

    // The same bytes, to see what reached the region
    Field (NVSM, ByteAcc, NoLock, Preserve) {
        RAW0, 8,
        RIDX, 8,
        RDAT, 8,
        RBNK, 8,
        RBDT, 8,
    }

    IndexField (IDXR, DATR, ByteAcc, NoLock, Preserve) {
        Offset (0x10),
        IFU0, 8,
    }

    BankField (NVSM, BNKR, 0x5A, ByteAcc, NoLock, Preserve) {
        Offset (4),
        BKU0, 8,
    }

    Name (BUF0, Buffer (4) { 0 })
    CreateByteField (BUF0, 1, BFD0)

    // The shape of firmware EC helpers, e.g. ECWT (Value, RefOf (Field))
    Method (WRTE, 2) {
        Arg1 = Arg0
    }

    Method (COPY, 2) {
        CopyObject (Arg0, Arg1)
    }

    Method (ADD1, 2) {
        Add (Arg0, 1, Arg1)
    }

    Method (INCR, 1) {
        Arg0++
    }

    Method (PASS, 2) {
        WRTE (Arg0, Arg1)
    }

    Method (MAIN) {
        WRTE (0x11, RefOf (FLD0))
        CHK ("Store to a field via ArgX", RAW0, 0x11)
        CHK ("Field type after a store via ArgX", ObjectType (FLD0), 5)

        COPY (0x22, RefOf (FLD0))
        CHK ("CopyObject to a field via ArgX", RAW0, 0x22)
        CHK ("Field type after a CopyObject via ArgX", ObjectType (FLD0), 5)

        ADD1 (0x32, RefOf (FLD0))
        CHK ("Add to a field via ArgX", RAW0, 0x33)

        INCR (RefOf (FLD0))
        CHK ("Increment of a field via ArgX", RAW0, 0x34)

        Local0 = RefOf (FLD0)
        Local0++
        CHK ("Increment of a field via LocalX", RAW0, 0x35)

        PASS (0x44, RefOf (FLD0))
        CHK ("Store to a field via a reference passed on", RAW0, 0x44)

        Local1 = RefOf (FLD0)
        WRTE (0x55, RefOf (Local1))
        CHK ("Store to a field via ArgX via LocalX", RAW0, 0x55)

        FLD0 = 0x66
        CHK ("Direct store to the field afterwards", RAW0, 0x66)

        CopyObject (0x67, FLD0)
        CHK ("CopyObject to a field", RAW0, 0x67)
        CHK ("Field type after a CopyObject", ObjectType (FLD0), 5)

        WRTE (0x77, RefOf (IFU0))
        CHK ("Index register after a store via ArgX", RIDX, 0x10)
        CHK ("Data register after a store via ArgX", RDAT, 0x77)

        WRTE (0x88, RefOf (BKU0))
        CHK ("Bank register after a store via ArgX", RBNK, 0x5A)
        CHK ("Banked data after a store via ArgX", RBDT, 0x88)

        WRTE (0x99, RefOf (BFD0))
        CHK ("Store to a buffer field via ArgX", DerefOf (BUF0[1]), 0x99)
        CHK ("Buffer field type after a store via ArgX",
             ObjectType (BFD0), 14)

        COPY (0xAA, RefOf (BFD0))
        CHK ("CopyObject to a buffer field via ArgX", DerefOf (BUF0[1]), 0xAA)
        CHK ("Buffer field type after a CopyObject via ArgX",
             ObjectType (BFD0), 14)

        INCR (RefOf (BFD0))
        CHK ("Increment of a buffer field via ArgX", DerefOf (BUF0[1]), 0xAB)

        CopyObject (0xBB, BFD0)
        CHK ("CopyObject to a buffer field", DerefOf (BUF0[1]), 0xBB)
        CHK ("Buffer field type after a CopyObject", ObjectType (BFD0), 14)

        Return (FAIL)
    }
}
