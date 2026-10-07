// Name: Event reset
// Expect: int => 0

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN, 0, Serialized)
    {
        Event (EVET)

        // Resetting an event that was never signaled is fine
        Reset(EVET)

        If (Wait(EVET, Zero) == Zero) {
            Return (1)
        }

        // No matter how many times it was signaled, a reset undoes them all
        Local0 = 5
        While (Local0--) {
            Signal(EVET)
        }

        Reset(EVET)

        If (Wait(EVET, Zero) == Zero) {
            Return (2)
        }

        If (Wait(EVET, 10) == Zero) {
            Return (3)
        }

        // The event is still perfectly usable afterwards
        Signal(EVET)
        Signal(EVET)

        If (Wait(EVET, Zero) != Zero) {
            Return (4)
        }

        If (Wait(EVET, 0xFFFF) != Zero) {
            Return (5)
        }

        If (Wait(EVET, Zero) == Zero) {
            Return (6)
        }

        Return (0)
    }
}
