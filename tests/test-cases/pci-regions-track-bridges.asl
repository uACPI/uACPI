// Name: PCI_Config regions track the current state of the bridges
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
     * 10:18.0 - PCI-to-PCI bridge, not configured (secondary bus 0)
     * 10:19.0 - PCI-to-PCI bridge, secondary bus 0x1B (nothing can be opened
     *           on that bus)
     * 19:00.0 - endpoint
     * 1A:00.0 - endpoint
     *
     * The secondary bus number of both bridges can be set by writing to the
     * register at 0x40, which is something the test runner provides so that
     * the header of the bridge doesn't have to be touched.
     */
    Device (PCI0) {
        Name (_HID, "PNP0A08")
        Name (_SEG, 0xCAFE)
        Name (_BBN, 0x10)

        Device (RP01) {
            Name (_ADR, 0x00180000)

            OperationRegion (CFG, PCI_Config, 0, 0x48)
            Field (CFG, ByteAcc, NoLock) {
                Offset (0x19),
                SBUS, 8,
                Offset (0x40),
                WBUS, 8
            }

            Device (PXSX) {
                Name (_ADR, 0)

                OperationRegion (CFG, PCI_Config, 0, 4)
                Field (CFG, DWordAcc, NoLock) { ID, 32 }
            }
        }

        Device (RP02) {
            Name (_ADR, 0x00190000)

            OperationRegion (CFG, PCI_Config, 0, 0x48)
            Field (CFG, ByteAcc, NoLock) {
                Offset (0x19),
                SBUS, 8,
                Offset (0x40),
                WBUS, 8
            }

            Device (PXSX) {
                Name (_ADR, 0)

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

        // The bridge above the device is not configured yet
        CHK ("unconfigured bridge", \PCI0.RP01.SBUS, 0)
        CHK ("device below an unconfigured bridge", \PCI0.RP01.PXSX.ID,
             0xFFFFFFFF)
        \PCI0.RP01.PXSX.ID = 0x12345678

        \PCI0.RP01.WBUS = 0x1A
        CHK ("device below a now configured bridge", \PCI0.RP01.PXSX.ID,
             0xA0001A00)

        // The region must follow the bridge if it's moved to a different bus
        \PCI0.RP01.WBUS = 0x19
        CHK ("device below a moved bridge", \PCI0.RP01.PXSX.ID, 0xA0001900)

        \PCI0.RP01.WBUS = 0
        CHK ("device below a deconfigured bridge", \PCI0.RP01.PXSX.ID,
             0xFFFFFFFF)

        \PCI0.RP01.WBUS = 0x1A
        CHK ("device below a reconfigured bridge", \PCI0.RP01.PXSX.ID,
             0xA0001A00)

        // The bridge is fine, but the device itself can't be opened
        CHK ("bridge to nowhere", \PCI0.RP02.SBUS, 0x1B)
        CHK ("device that doesn't exist", \PCI0.RP02.PXSX.ID, 0xFFFFFFFF)
        \PCI0.RP02.PXSX.ID = 0x12345678

        \PCI0.RP02.WBUS = 0x1A
        CHK ("device that now exists", \PCI0.RP02.PXSX.ID, 0xA0001A00)

        // It must stay there once found
        CHK ("device that still exists", \PCI0.RP02.PXSX.ID, 0xA0001A00)

        Return (FAIL)
    }
}
