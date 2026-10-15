// Name: Empty buffers can be created
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

    Method (MAIN) {
        Local0 = Buffer (Zero) { }
        CHK ("Type of an empty buffer", ObjectType (Local0), 3)
        CHK ("Size of an empty buffer", SizeOf (Local0), 0)

        Local1 = 0
        Local2 = Buffer (Local1) { }
        CHK ("Type of an empty buffer with a run-time size",
             ObjectType (Local2), 3)
        CHK ("Size of an empty buffer with a run-time size",
             SizeOf (Local2), 0)

        Return (FAIL)
    }
}
