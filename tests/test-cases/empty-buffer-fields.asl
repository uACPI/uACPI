// Name: CreateField with a length of 0 makes a buffer field that does nothing
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

    Name (BUF0, Buffer { 1, 2, 3, 4 })

    Method (MAIN) {
        CreateField (BUF0, 0, 0, BZ0)
        CreateField (BUF0, 13, 0, BZ1)

        CHK ("Type of an empty buffer field", ObjectType (BZ0), 14)

        // Reading one gives an empty buffer
        Local0 = BZ0
        CHK ("Type of a read from an empty buffer field",
             ObjectType (Local0), 3)
        CHK ("Size of a read from an empty buffer field", SizeOf (Local0), 0)

        BZ0 = 0xFF
        BZ0 = "Hello"
        BZ0 = Buffer { 0x11, 0x22 }
        BZ1 = 0xFF
        CHK ("Buffer after writes to its empty fields", BUF0,
             Buffer { 1, 2, 3, 4 })

        Return (FAIL)
    }
}
