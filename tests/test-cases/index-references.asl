// Name: Index() references keep pointing at the element they were made for
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

    Name (INT0, 0)
    Name (PKG0, Package { 1, "two", Buffer { 3 } })
    Name (BUF0, Buffer { 1, 2, 3 })

    Method (WRTE, 2) {
        Arg1 = Arg0
    }

    Method (COPY, 2) {
        CopyObject (Arg0, Arg1)
    }

    Method (INCR, 1) {
        Arg0++
    }

    Method (MAIN) {
        // Buffer indices
        Local0 = Buffer { 1, 2, 3 }
        WRTE (0x1234, Index (Local0, 1))
        CHK ("Store to a buffer index via ArgX", DerefOf (Local0[1]), 0x34)

        COPY (0x41, Index (Local0, 1))
        CHK ("CopyObject to a buffer index via ArgX",
             DerefOf (Local0[1]), 0x41)

        INCR (Index (Local0, 1))
        CHK ("Increment of a buffer index via ArgX",
             DerefOf (Local0[1]), 0x42)

        WRTE (0x51, Index (BUF0, 2))
        CHK ("Store to an index of a named buffer via ArgX",
             DerefOf (BUF0[2]), 0x51)

        Local1 = Index (Local0, 2)
        Local1 = 0x61
        CHK ("Store to a buffer index via LocalX", DerefOf (Local0[2]), 0x61)

        WRTE (0x62, Local1)
        CHK ("Store to a buffer index passed on from a LocalX",
             DerefOf (Local0[2]), 0x62)

        Local2 = Index (Local0, 0)
        WRTE (0x71, RefOf (Local2))
        CHK ("Store to a buffer index via ArgX via LocalX",
             DerefOf (Local0[0]), 0x71)

        // Package indices
        Local3 = Package { 1, 2, 3 }
        WRTE ("str", Index (Local3, 1))
        CHK ("Element type after a store via ArgX",
             ObjectType (DerefOf (Local3[1])), 2)
        CHK ("Store to a package index via ArgX", DerefOf (Local3[1]), "str")

        COPY (0x12, Index (Local3, 1))
        CHK ("CopyObject to a package index via ArgX",
             DerefOf (Local3[1]), 0x12)

        INCR (Index (Local3, 1))
        CHK ("Increment of a package index via ArgX",
             DerefOf (Local3[1]), 0x13)

        WRTE (0x22, Index (PKG0, 1))
        CHK ("Store to an index of a named package via ArgX",
             DerefOf (PKG0[1]), 0x22)

        Local4 = Index (Local3, 2)
        WRTE ("abc", Local4)
        CHK ("Store to a package index passed on from a LocalX",
             DerefOf (Local3[2]), "abc")

        // The slot is what counts, not the element that was there at first
        COPY (0x44, Index (Local3, 2))
        CHK ("Read via a package index after the element was replaced",
             DerefOf (Local4), 0x44)

        // An element that's itself a reference is followed
        Local3[0] = RefOf (INT0)
        WRTE (0x55, Index (Local3, 0))
        CHK ("Store via a package index holding a reference", INT0, 0x55)

        Return (FAIL)
    }
}
