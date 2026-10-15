// Name: A store via ArgX doesn't overwrite objects that aren't data
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

    Method (COPY, 2) {
        CopyObject (Arg0, Arg1)
    }

    Device (DEV0) {
        Name (_HID, "TEST0000")
    }
    Event (EVT0)
    Method (MET0) {
        Return (0)
    }
    Mutex (MTX0, 0)
    OperationRegion (REG0, SystemMemory, 0x100000, 0x10)
    PowerResource (PWR0, 0, 0) {
        Method (_STA) {
            Return (0)
        }
        Method (_ON) { }
        Method (_OFF) { }
    }
    Processor (CPU0, 0, 0, 0) { }
    ThermalZone (TZ00) { }

    Mutex (MTX1, 0)

    /*
     * Each of these is an AML error that aborts the store. Doing them from
     * table-level code lets the rest of the table load regardless.
     */
    WRTE (0x123, RefOf (DEV0))
    WRTE (0x123, RefOf (EVT0))
    WRTE (0x123, RefOf (MET0))
    WRTE (0x123, RefOf (MTX0))
    WRTE (0x123, RefOf (REG0))
    WRTE (0x123, RefOf (PWR0))
    WRTE (0x123, RefOf (CPU0))
    WRTE (0x123, RefOf (TZ00))

    Method (MAIN) {
        CHK ("Device after a store via ArgX", ObjectType (DEV0), 6)
        CHK ("Event after a store via ArgX", ObjectType (EVT0), 7)
        CHK ("Method after a store via ArgX", ObjectType (MET0), 8)
        CHK ("Mutex after a store via ArgX", ObjectType (MTX0), 9)
        CHK ("OperationRegion after a store via ArgX",
             ObjectType (REG0), 10)
        CHK ("PowerResource after a store via ArgX", ObjectType (PWR0), 11)
        CHK ("Processor after a store via ArgX", ObjectType (CPU0), 12)
        CHK ("ThermalZone after a store via ArgX", ObjectType (TZ00), 13)

        // CopyObject is allowed to do it
        COPY (0x123, RefOf (MTX1))
        CHK ("Mutex after a CopyObject via ArgX", ObjectType (MTX1), 1)
        CHK ("Value after a CopyObject via ArgX", MTX1, 0x123)

        Return (FAIL)
    }
}
