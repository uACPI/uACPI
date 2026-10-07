// Name: A mutex or an event can be overwritten while someone is waiting on it
// Expect: str => check-aml-with-threads

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-aml-with-threads")
    }

    Mutex (MUTX, 0)
    Event (GATE)
    Event (EVET)

    // How far the other threads have made it
    Name (STAT, 0)

    Name (TOOK, 0xFF)
    Name (WOKE, 0xFF)

    /*
     * The test runner executes WORK on a thread of its own every time that the
     * device is notified. This one holds MUTX until it's told to let go, which
     * it does by returning.
     */
    Device (HLDR) {
        Name (_HID, "TEST0000")

        Method (WORK, 1) {
            Acquire (MUTX, 0xFFFF)
            STAT = 1
            Wait (GATE, 0xFFFF)
        }
    }

    Device (WTER) {
        Name (_HID, "TEST0001")

        Method (WORK, 1) {
            If (Arg0 == 0) {
                // Wants MUTX as well, and has to wait for it
                STAT = 2
                TOOK = Acquire (MUTX, 0xFFFF)
                STAT = 3
            } Else {
                // Nobody is going to signal this event, so this times out
                STAT = 4
                WOKE = Wait (EVET, 1000)
                STAT = 5
            }
        }
    }

    /*
     * Sleep until the other threads make it to the state that we want. They
     * are only ever seen in the middle of an operation that blocks, as that's
     * the only time that we're able to run at all.
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

    Method (TEST) {
        /*
         * Have one thread hold a mutex, and another one wait for it. Then get
         * rid of the mutex object, and only then let go of the mutex itself:
         * the thread that is waiting must still be able to acquire it.
         */
        Notify (HLDR, 0)
        If (!WFOR (1)) {
            Return (Zero)
        }

        Notify (WTER, 0)
        If (!WFOR (2)) {
            Return (Zero)
        }

        CopyObject (Zero, MUTX)
        Signal (GATE)

        If (!WFOR (3)) {
            Return (Zero)
        }

        If (TOOK != Zero) {
            Printf("Unable to acquire a mutex that was overwritten: %o", TOOK)
            Return (Zero)
        }

        // Same thing for an event, which must stay around until the wait is over
        Notify (WTER, 1)
        If (!WFOR (4)) {
            Return (Zero)
        }

        CopyObject (Zero, EVET)

        // Make sure the event was gone while the wait was still in progress
        If (WOKE != 0xFF) {
            Printf("The wait was over too early: %o", WOKE)
            Return (Zero)
        }

        If (!WFOR (5)) {
            Return (Zero)
        }

        // Nobody was able to signal it, so the only way out is a timeout
        If (WOKE == Zero) {
            Printf("The wait has not timed out")
            Return (Zero)
        }

        Return (Ones)
    }
}
