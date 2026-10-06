// Name: PCI_Config regions are attached to the correct PCI device
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

    /*
     * The test runner provides the following devices on segment 0xCAFE:
     * 10:00.0 - endpoint
     * 10:02.0 - endpoint
     * 10:03.0 - endpoint
     * 10:1C.0 - PCI-to-PCI bridge, secondary bus 0x15
     * 10:1D.0 - PCI-to-PCI bridge, not configured (secondary bus 0)
     * 10:1F.0 - CardBus bridge, secondary bus 0x19
     * 15:00.0 - endpoint
     * 15:01.0 - PCI-to-PCI bridge, secondary bus 0x16
     * 16:02.3 - endpoint
     * 19:00.0 - endpoint
     */
    Device (PCI0) {
        Name (_HID, "PNP0A08")
        Name (_SEG, 0xCAFE)
        Name (_BBN, 0x10)

        OperationRegion (CFG, PCI_Config, 0, 4)
        Field (CFG, DWordAcc, NoLock) { ID, 32 }

        Device (RP01) {
            Name (_ADR, 0x001C0000)

            OperationRegion (CFG, PCI_Config, 0, 4)
            Field (CFG, DWordAcc, NoLock) { ID, 32 }

            Device (PXSX) {
                Name (_ADR, 0)

                OperationRegion (CFG, PCI_Config, 0, 4)
                Field (CFG, DWordAcc, NoLock) { ID, 32 }
            }

            // Nothing below a device without an _ADR is a PCI device
            Device (CONT) {
                OperationRegion (CFG, PCI_Config, 0, 4)
                Field (CFG, DWordAcc, NoLock) { ID, 32 }

                Device (PXSX) {
                    Name (_ADR, 0)

                    OperationRegion (CFG, PCI_Config, 0, 4)
                    Field (CFG, DWordAcc, NoLock) { ID, 32 }
                }
            }

            Device (BRG2) {
                Name (_ADR, 0x00010000)

                Device (DEV0) {
                    Name (_ADR, 0x00020003)

                    OperationRegion (CFG, PCI_Config, 0, 4)
                    Field (CFG, DWordAcc, NoLock) { ID, 32 }
                }
            }
        }

        // The bridge exists, but has no secondary bus assigned
        Device (RP02) {
            Name (_ADR, 0x001D0000)

            OperationRegion (CFG, PCI_Config, 0, 4)
            Field (CFG, DWordAcc, NoLock) { ID, 32 }

            Device (PXSX) {
                Name (_ADR, 0)

                OperationRegion (CFG, PCI_Config, 0, 4)
                Field (CFG, DWordAcc, NoLock) { ID, 32 }
            }
        }

        // The bridge doesn't exist at all
        Device (RP03) {
            Name (_ADR, 0x001E0000)

            Device (PXSX) {
                Name (_ADR, 0)

                OperationRegion (CFG, PCI_Config, 0, 4)
                Field (CFG, DWordAcc, NoLock) { ID, 32 }
            }
        }

        Device (CBUS) {
            Name (_ADR, 0x001F0000)

            Device (CARD) {
                Name (_ADR, 0)

                OperationRegion (CFG, PCI_Config, 0, 4)
                Field (CFG, DWordAcc, NoLock) { ID, 32 }
            }
        }

        /*
         * Not a bridge, so whatever is below it is not a PCI device even if it
         * has an _ADR, e.g. a port of a USB controller.
         */
        Device (EP00) {
            Name (_ADR, 0x00020000)

            Device (CHLD) {
                Name (_ADR, 0x00030000)

                OperationRegion (CFG, PCI_Config, 0, 4)
                Field (CFG, DWordAcc, NoLock) { ID, 32 }
            }

            Device (PRT1) {
                Name (_ADR, 1)

                OperationRegion (CFG, PCI_Config, 0, 4)
                Field (CFG, DWordAcc, NoLock) { ID, 32 }
            }
        }
    }

    Method (MAIN, 0, NotSerialized)
    {
        // The PCI devices used here only exist in the uACPI test runner
        If (!_OSI ("TestRunner")) {
            Return (0)
        }

        CHK ("root without an _ADR", \PCI0.ID, 0xFFFFFFFF)
        CHK ("bridge", \PCI0.RP01.ID, 0xA000001C)
        CHK ("device below a bridge", \PCI0.RP01.PXSX.ID, 0xA0001500)
        CHK ("container below a bridge", \PCI0.RP01.CONT.ID, 0xA000001C)
        CHK ("device in a container", \PCI0.RP01.CONT.PXSX.ID, 0xA000001C)
        CHK ("device below two bridges", \PCI0.RP01.BRG2.DEV0.ID, 0xA0001623)
        CHK ("unconfigured bridge", \PCI0.RP02.ID, 0xA000001D)
        CHK ("device below an unconfigured bridge", \PCI0.RP02.PXSX.ID,
             0xFFFFFFFF)
        CHK ("device below a missing bridge", \PCI0.RP03.PXSX.ID, 0xFFFFFFFF)
        CHK ("device below a CardBus bridge", \PCI0.CBUS.CARD.ID, 0xA0001900)
        CHK ("device below an endpoint", \PCI0.EP00.CHLD.ID, 0xA0000002)
        CHK ("port below an endpoint", \PCI0.EP00.PRT1.ID, 0xA0000002)

        // Writes to an unreachable device must not blow up
        \PCI0.RP02.PXSX.ID = 0x12345678

        Return (FAIL)
    }
}
