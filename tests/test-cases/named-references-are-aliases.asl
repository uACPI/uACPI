// Name: A name that holds a reference is an alias of what it refers to
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

    Method (WRTE, 2) {
        Arg1 = Arg0
    }

    Method (ADD1, 1) {
        Return (Arg0 + 1)
    }

    Name (TGT0, 0x1234)
    Name (TGT1, 0x5678)
    Name (PKG0, Package { 1, 2, 3 })
    Name (BUF0, Buffer { 1, 2, 3 })

    OperationRegion (NVSM, SystemMemory, 0x100000, 0x10)
    Field (NVSM, ByteAcc, NoLock, Preserve) {
        FLD0, 8,
    }
    Field (NVSM, ByteAcc, NoLock, Preserve) {
        RAW0, 8,
    }

    // These end up holding a reference
    Name (ALS0, 0)
    Name (ALS1, 0)
    Name (ALS2, 0)
    Name (ALS3, 0)
    Name (ALS4, 0)

    Method (RETN) {
        Return (ALS0)
    }

    Method (MAIN) {
        WRTE (RefOf (TGT0), RefOf (ALS0))
        CHK ("Read of an alias", ALS0, 0x1234)

        TGT0 = 0x99
        CHK ("Read of an alias after a store to its target", ALS0, 0x99)
        CHK ("Alias passed to a method", ADD1 (ALS0), 0x9A)
        CHK ("Alias returned from a method", RETN (), 0x99)

        ALS0 = 0x55
        CHK ("Store to an alias", TGT0, 0x55)

        CopyObject ("str", TGT0)
        CHK ("Type of an alias after its target was replaced",
             ObjectType (ALS0), 2)
        CHK ("Read of an alias after its target was replaced", ALS0, "str")

        CopyObject (0x66, ALS0)
        CHK ("CopyObject to an alias", TGT0, 0x66)
        CHK ("Read of an alias after a CopyObject to it", ALS0, 0x66)

        CopyObject (RefOf (TGT1), ALS1)
        CHK ("Read of an alias made with CopyObject", ALS1, 0x5678)

        // A package element can be aliased, but CopyObject replaces the alias
        WRTE (Index (PKG0, 1), RefOf (ALS2))
        CHK ("Read of an alias of a package element", ALS2, 2)

        PKG0[1] = 0x77
        CHK ("Read of an alias of a package element after a store",
             ALS2, 0x77)

        CopyObject ("ab", ALS2)
        CHK ("CopyObject to an alias of a package element", ALS2, "ab")
        CHK ("Package element after a CopyObject to its alias",
             DerefOf (PKG0[1]), 0x77)

        WRTE (Index (BUF0, 1), RefOf (ALS3))
        CHK ("Read of an alias of a buffer index", ALS3, 2)

        ALS3 = 0x41
        CHK ("Store to an alias of a buffer index", DerefOf (BUF0[1]), 0x41)

        CopyObject (0x42, ALS3)
        CHK ("CopyObject to an alias of a buffer index",
             DerefOf (BUF0[1]), 0x42)

        WRTE (RefOf (FLD0), RefOf (ALS4))
        RAW0 = 0x12
        CHK ("Read of an alias of a field", ALS4, 0x12)

        ALS4 = 0x34
        CHK ("Store to an alias of a field", RAW0, 0x34)

        CopyObject (0x56, ALS4)
        CHK ("CopyObject to an alias of a field", RAW0, 0x56)
        CHK ("Field type after a CopyObject to its alias", ObjectType (FLD0), 5)

        Return (FAIL)
    }
}
