// Name: The global lock is taken from and given back to the firmware
// Expect: int => 0

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Method (MAIN, 0, Serialized)
    {
        /*
         * This is only expected to work if the host actually does the
         * handshake with the firmware, which acpiexec for example doesn't.
         */
        If (!_OSI ("TestRunner")) {
            Debug = "Not a uACPI test runner, skipping"
            Return (0)
        }

        DataTableRegion (FACS, "FACS", "", "")
        Field (FACS, DWordAcc, NoLock, Preserve) {
            Offset (16),
            GLCK, 32,
        }

        // Bit 0 is pending, bit 1 is owned
        Local0 = GLCK & 3
        If (Local0 != 0) {
            Printf("The global lock is not free to begin with: %o", Local0)
            Return (1)
        }

        If (Acquire (\_GL, 0xFFFF)) {
            Debug = "Failed to acquire the global lock"
            Return (2)
        }

        // Owned, and nobody else wants it
        Local0 = GLCK & 3
        If (Local0 != 2) {
            Printf("The global lock is not owned after an acquire: %o", Local0)
            Release (\_GL)
            Return (3)
        }

        // The firmware wants the lock now, both bits must be gone afterwards
        GLCK |= 1
        Release (\_GL)

        Local0 = GLCK & 3
        If (Local0 != 0) {
            Printf("The global lock is not free after a release: %o", Local0)
            Return (4)
        }

        Return (0)
    }
}
