// Name: A field can be overwritten while it's being accessed
// Expect: str => check-aml-with-threads

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-aml-with-threads")
    }

    OperationRegion (REG0, SystemMemory, 0x100000, 0x10)

    /*
     * These are only accessed with the global lock held, which makes it
     * possible to stop an access right after it has started: all it takes is
     * holding the lock ourselves.
     */
    Field (REG0, ByteAcc, Lock, Preserve) {
        FLD0, 8,
        FLD1, 8,

        // These take more than one access to write
        FLD2, 16,
        FLD3, 64,
    }

    // Same memory, but accessible at any time
    Field (REG0, ByteAcc, NoLock, Preserve) {
        RAW0, 8,
        RAW1, 8,
        RAW2, 16,
        RAW3, 64,
    }

    Name (INT0, 0x1234)
    Name (BUF0, Buffer { 1, 2, 3, 4, 5, 6, 7, 8 })

    // How far the other thread has made it
    Name (STAT, 0)

    Name (RVAL, 0)

    /*
     * The test runner executes WORK on a thread of its own every time that the
     * device is notified.
     */
    Device (THR0) {
        Name (_HID, "TEST0000")

        Method (WORK, 1) {
            STAT = 1

            If (Arg0 == 0) {
                RVAL = FLD0
            } ElseIf (Arg0 == 1) {
                FLD1 = 0xAB
            } ElseIf (Arg0 == 2) {
                FLD2 = INT0
            } Else {
                FLD3 = BUF0
            }

            STAT = 2
        }
    }

    /*
     * Sleep until the other thread makes it to the state that we want. It is
     * only ever seen in the middle of an operation that blocks, as that's the
     * only time that we're able to run at all.
     */
    Method (WFOR, 1) {
        Local0 = 0

        While (STAT != Arg0) {
            If (Local0 >= 10000) {
                Printf("Stuck in state %o, expected %o", STAT, Arg0)
                Return (Zero)
            }

            Sleep (1)
            Local0++
        }

        Return (Ones)
    }

    // Get the other thread stuck in the middle of the access number Arg0
    Method (STRT, 1) {
        STAT = 0

        Acquire (\_GL, 0xFFFF)
        Notify (THR0, Arg0)

        Return (WFOR (1))
    }

    // Let the other thread finish what it's doing
    Method (FINI) {
        Release (\_GL)
        Return (WFOR (2))
    }

    Method (TEST) {
        RAW0 = 0x5A

        /*
         * The namespace is unlocked while an access is waiting for the global
         * lock, so nothing prevents the field from being overwritten at that
         * point. Whoever is doing the access must still be able to finish it.
         */
        If (!STRT (0)) {
            Return (Zero)
        }

        CopyObject (Zero, FLD0)

        If (!FINI ()) {
            Return (Zero)
        }

        If (RVAL != 0x5A) {
            Printf("Read %o from a field that was overwritten", RVAL)
            Return (Zero)
        }

        If (!STRT (1)) {
            Return (Zero)
        }

        CopyObject (Zero, FLD1)

        If (!FINI ()) {
            Return (Zero)
        }

        If (RAW1 != 0xAB) {
            Printf("Wrote %o to a field that was overwritten", RAW1)
            Return (Zero)
        }

        /*
         * Same thing for the object that a field is written from, as it's
         * what the data comes from once the access gets to proceed.
         */
        If (!STRT (2)) {
            Return (Zero)
        }

        CopyObject (Zero, INT0)

        If (!FINI ()) {
            Return (Zero)
        }

        If (RAW2 != 0x1234) {
            Printf("Wrote %o from an integer that was overwritten", RAW2)
            Return (Zero)
        }

        If (!STRT (3)) {
            Return (Zero)
        }

        CopyObject (Zero, BUF0)

        If (!FINI ()) {
            Return (Zero)
        }

        If (RAW3 != 0x0807060504030201) {
            Printf("Wrote %o from a buffer that was overwritten", RAW3)
            Return (Zero)
        }

        Return (Ones)
    }
}
