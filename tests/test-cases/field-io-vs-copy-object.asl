// Name: What a field is written from can be overwritten mid-access
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
        // These take more than one access to write
        FLD2, 16,
        FLD3, 64,
    }

    // Same memory, but accessible at any time
    Field (REG0, ByteAcc, NoLock, Preserve) {
        RAW2, 16,
        RAW3, 64,
    }

    Name (INT0, 0x1234)
    Name (BUF0, Buffer { 1, 2, 3, 4, 5, 6, 7, 8 })

    // How far the other thread has made it
    Name (STAT, 0)

    /*
     * The test runner executes WORK on a thread of its own every time that the
     * device is notified.
     */
    Device (THR0) {
        Name (_HID, "TEST0000")

        Method (WORK, 1) {
            STAT = 1

            If (Arg0 == 0) {
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
        /*
         * The namespace is unlocked while an access is waiting for the global
         * lock, so nothing prevents the object that a field is written from
         * from being overwritten at that point, and it's what the data comes
         * from once the access gets to proceed. The field itself can't be
         * overwritten, NT stores to it even via CopyObject.
         */
        If (!STRT (0)) {
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

        If (!STRT (1)) {
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
