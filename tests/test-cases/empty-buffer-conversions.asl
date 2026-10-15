// Name: Empty buffers can be concatenated and converted to strings
// Expect: int => 0

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Name (FAIL, 0)

    Method (CHK, 3) {
        If (ObjectType (Arg1) != ObjectType (Arg2)) {
            Printf ("%o: expected type %o, got %o", Arg0,
                    ToDecimalString (ObjectType (Arg2)),
                    ToDecimalString (ObjectType (Arg1)))
            FAIL++
            Return ()
        }
        If (SizeOf (Arg1) != SizeOf (Arg2)) {
            Printf ("%o: expected size %o, got %o", Arg0,
                    ToDecimalString (SizeOf (Arg2)),
                    ToDecimalString (SizeOf (Arg1)))
            FAIL++
            Return ()
        }
        If (SizeOf (Arg1) && Arg1 != Arg2) {
            Printf ("%o: expected %o, got %o", Arg0, Arg2, Arg1)
            FAIL++
        }
    }

    Method (MAIN) {
        // An empty buffer, Mid() past the end makes one
        Local0 = Mid (Buffer { 1 }, 5, 1)
        CHK ("Empty buffer", Local0, Mid (Buffer { 1 }, 5, 1))

        CHK ("Empty buffer + empty buffer", Concatenate (Local0, Local0),
             Local0)
        CHK ("Empty buffer + buffer", Concatenate (Local0, Buffer { 7 }),
             Buffer { 7 })
        CHK ("Buffer + empty buffer", Concatenate (Buffer { 7 }, Local0),
             Buffer { 7 })
        CHK ("String + empty buffer", Concatenate ("ab", Local0), "ab")
        CHK ("Empty string + empty buffer", Concatenate ("", Local0), "")
        CHK ("Empty buffer + string", Concatenate (Local0, "ab"),
             Buffer { 0x61, 0x62, 0x00 })

        CHK ("ToHexString of an empty buffer", ToHexString (Local0), "")
        CHK ("ToDecimalString of an empty buffer", ToDecimalString (Local0),
             "")
        CHK ("ToString of an empty buffer", ToString (Local0), "")

        Return (FAIL)
    }
}
