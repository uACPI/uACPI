// Name: Access to non-existent PCI devices should work
// Expect: int => 18446744073709551615

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Device (PCI0) {
        Name (_HID, "PNP0A03")
        Name (_SEG, 0xDEAD)

        Device (XHCI) {
            Name (_ADR, 0x00030002)

            OperationRegion(HREG, PCI_Config, 0x10, 0xF0)
            Field (HREG, ByteAcc, NoLock) {
                REG0, 8
            }
            Field (HREG, WordAcc, NoLock) {
                REG1, 16
            }
            Field (HREG, DWordAcc, NoLock) {
                REG2, 32
            }
        }
    }

    Method (MAIN, 0, NotSerialized)
    {
        // Test that writes don't blow up
        \PCI0.XHCI.REG0 = 0xFF
        \PCI0.XHCI.REG1 = 0xFFFF
        \PCI0.XHCI.REG2 = 0xFFFFFFFF

        // Reads should return FFs 
        Return (\PCI0.XHCI.REG0 == 0xFF &&
                \PCI0.XHCI.REG1 == 0xFFFF &&
                \PCI0.XHCI.REG2 == 0xFFFFFFFF)
    }
}
