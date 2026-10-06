// Name: Writes to the header of a PCI device are filtered
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
     * 10:02.0 - endpoint
     * 10:1C.0 - PCI-to-PCI bridge
     * 10:1F.0 - CardBus bridge
     *
     * The configuration space of these is plain memory.
     */
    Device (PCI0) {
        Name (_HID, "PNP0A08")
        Name (_SEG, 0xCAFE)
        Name (_BBN, 0x10)

        Device (EP00) {
            Name (_ADR, 0x00020000)

            OperationRegion (CFG, PCI_Config, 0, 0x48)
            Field (CFG, ByteAcc, NoLock) {
                Offset (0x04), B04, 8,
                Offset (0x0C), B0C, 8,
                Offset (0x2B), B2B, 8, B2C, 8,
                Offset (0x2F), B2F, 8, B30, 8,
                Offset (0x3B), B3B, 8, B3C, 8,
                Offset (0x3F), B3F, 8,
                Offset (0x44), B44, 8,
            }
            Field (CFG, DWordAcc, NoLock) {
                Offset (0x10), D10, 32,
                Offset (0x28), D28, 32, D2C, 32,
                Offset (0x38), D38, 32, D3C, 32,
                Offset (0x44), D44, 32,
            }
        }

        Device (RP01) {
            Name (_ADR, 0x001C0000)

            OperationRegion (CFG, PCI_Config, 0, 0x48)
            Field (CFG, ByteAcc, NoLock) {
                Offset (0x04), B04, 8,
                Offset (0x0C), B0C, 8,
                Offset (0x2B), B2B, 8, B2C, 8,
                Offset (0x2F), B2F, 8, B30, 8,
                Offset (0x3B), B3B, 8, B3C, 8,
                Offset (0x3F), B3F, 8,
                Offset (0x44), B44, 8,
            }
            Field (CFG, DWordAcc, NoLock) {
                Offset (0x10), D10, 32,
                Offset (0x28), D28, 32, D2C, 32,
                Offset (0x38), D38, 32, D3C, 32,
                Offset (0x44), D44, 32,
            }
        }

        Device (CBUS) {
            Name (_ADR, 0x001F0000)

            OperationRegion (CFG, PCI_Config, 0, 0x48)
            Field (CFG, ByteAcc, NoLock) {
                Offset (0x04), B04, 8,
                Offset (0x0C), B0C, 8,
                Offset (0x2B), B2B, 8, B2C, 8,
                Offset (0x2F), B2F, 8, B30, 8,
                Offset (0x3B), B3B, 8, B3C, 8,
                Offset (0x3F), B3F, 8,
                Offset (0x44), B44, 8,
            }
            Field (CFG, DWordAcc, NoLock) {
                Offset (0x10), D10, 32,
                Offset (0x28), D28, 32, D2C, 32,
                Offset (0x38), D38, 32, D3C, 32,
                Offset (0x44), D44, 32,
            }
        }
    }

    Method (MAIN, 0, NotSerialized)
    {
        // The PCI devices used here only exist in the uACPI test runner
        If (!_OSI ("TestRunner")) {
            Return (0)
        }

        /*
         * Try to flip a few bits everywhere, the value must only change for
         * the registers that AML is allowed to write to.
         */
        Local0 = \PCI0.EP00.B04
        \PCI0.EP00.B04 = (Local0 ^ 0x5A)
        CHK ("normal device: command", \PCI0.EP00.B04, Local0)

        Local0 = \PCI0.EP00.B0C
        \PCI0.EP00.B0C = (Local0 ^ 0x5A)
        CHK ("normal device: cache line size", \PCI0.EP00.B0C, Local0)

        Local0 = \PCI0.EP00.B2B
        \PCI0.EP00.B2B = (Local0 ^ 0x5A)
        CHK ("normal device: last byte before the subsystem IDs",
             \PCI0.EP00.B2B, Local0)

        Local0 = \PCI0.EP00.B2C
        \PCI0.EP00.B2C = (Local0 ^ 0x5A)
        CHK ("normal device: subsystem vendor ID",
             \PCI0.EP00.B2C, (Local0 ^ 0x5A))

        Local0 = \PCI0.EP00.B2F
        \PCI0.EP00.B2F = (Local0 ^ 0x5A)
        CHK ("normal device: subsystem ID", \PCI0.EP00.B2F, (Local0 ^ 0x5A))

        Local0 = \PCI0.EP00.B30
        \PCI0.EP00.B30 = (Local0 ^ 0x5A)
        CHK ("normal device: expansion ROM", \PCI0.EP00.B30, Local0)

        Local0 = \PCI0.EP00.B3B
        \PCI0.EP00.B3B = (Local0 ^ 0x5A)
        CHK ("normal device: last byte before the interrupt line",
             \PCI0.EP00.B3B, Local0)

        Local0 = \PCI0.EP00.B3C
        \PCI0.EP00.B3C = (Local0 ^ 0x5A)
        CHK ("normal device: interrupt line", \PCI0.EP00.B3C, (Local0 ^ 0x5A))

        Local0 = \PCI0.EP00.B3F
        \PCI0.EP00.B3F = (Local0 ^ 0x5A)
        CHK ("normal device: max latency", \PCI0.EP00.B3F, (Local0 ^ 0x5A))

        Local0 = \PCI0.EP00.B44
        \PCI0.EP00.B44 = (Local0 ^ 0x5A)
        CHK ("normal device: device-specific byte",
             \PCI0.EP00.B44, (Local0 ^ 0x5A))

        Local0 = \PCI0.EP00.D10
        \PCI0.EP00.D10 = (Local0 ^ 0x5A)
        CHK ("normal device: BAR", \PCI0.EP00.D10, Local0)

        Local0 = \PCI0.EP00.D28
        \PCI0.EP00.D28 = (Local0 ^ 0x5A)
        CHK ("normal device: dword before the subsystem IDs",
             \PCI0.EP00.D28, Local0)

        Local0 = \PCI0.EP00.D2C
        \PCI0.EP00.D2C = (Local0 ^ 0x5A)
        CHK ("normal device: subsystem IDs as a dword",
             \PCI0.EP00.D2C, (Local0 ^ 0x5A))

        Local0 = \PCI0.EP00.D38
        \PCI0.EP00.D38 = (Local0 ^ 0x5A)
        CHK ("normal device: dword before the interrupt line",
             \PCI0.EP00.D38, Local0)

        Local0 = \PCI0.EP00.D3C
        \PCI0.EP00.D3C = (Local0 ^ 0x5A)
        CHK ("normal device: interrupt line as a dword",
             \PCI0.EP00.D3C, (Local0 ^ 0x5A))

        Local0 = \PCI0.EP00.D44
        \PCI0.EP00.D44 = (Local0 ^ 0x5A)
        CHK ("normal device: device-specific dword",
             \PCI0.EP00.D44, (Local0 ^ 0x5A))

        Local0 = \PCI0.RP01.B04
        \PCI0.RP01.B04 = (Local0 ^ 0x5A)
        CHK ("PCI bridge: command", \PCI0.RP01.B04, Local0)

        Local0 = \PCI0.RP01.B0C
        \PCI0.RP01.B0C = (Local0 ^ 0x5A)
        CHK ("PCI bridge: cache line size", \PCI0.RP01.B0C, Local0)

        Local0 = \PCI0.RP01.B2B
        \PCI0.RP01.B2B = (Local0 ^ 0x5A)
        CHK ("PCI bridge: last byte before the subsystem IDs",
             \PCI0.RP01.B2B, Local0)

        Local0 = \PCI0.RP01.B2C
        \PCI0.RP01.B2C = (Local0 ^ 0x5A)
        CHK ("PCI bridge: subsystem vendor ID", \PCI0.RP01.B2C, Local0)

        Local0 = \PCI0.RP01.B2F
        \PCI0.RP01.B2F = (Local0 ^ 0x5A)
        CHK ("PCI bridge: subsystem ID", \PCI0.RP01.B2F, Local0)

        Local0 = \PCI0.RP01.B30
        \PCI0.RP01.B30 = (Local0 ^ 0x5A)
        CHK ("PCI bridge: expansion ROM", \PCI0.RP01.B30, Local0)

        Local0 = \PCI0.RP01.B3B
        \PCI0.RP01.B3B = (Local0 ^ 0x5A)
        CHK ("PCI bridge: last byte before the interrupt line",
             \PCI0.RP01.B3B, Local0)

        Local0 = \PCI0.RP01.B3C
        \PCI0.RP01.B3C = (Local0 ^ 0x5A)
        CHK ("PCI bridge: interrupt line", \PCI0.RP01.B3C, Local0)

        Local0 = \PCI0.RP01.B3F
        \PCI0.RP01.B3F = (Local0 ^ 0x5A)
        CHK ("PCI bridge: max latency", \PCI0.RP01.B3F, Local0)

        Local0 = \PCI0.RP01.B44
        \PCI0.RP01.B44 = (Local0 ^ 0x5A)
        CHK ("PCI bridge: device-specific byte",
             \PCI0.RP01.B44, (Local0 ^ 0x5A))

        Local0 = \PCI0.RP01.D10
        \PCI0.RP01.D10 = (Local0 ^ 0x5A)
        CHK ("PCI bridge: BAR", \PCI0.RP01.D10, Local0)

        Local0 = \PCI0.RP01.D28
        \PCI0.RP01.D28 = (Local0 ^ 0x5A)
        CHK ("PCI bridge: dword before the subsystem IDs",
             \PCI0.RP01.D28, Local0)

        Local0 = \PCI0.RP01.D2C
        \PCI0.RP01.D2C = (Local0 ^ 0x5A)
        CHK ("PCI bridge: subsystem IDs as a dword", \PCI0.RP01.D2C, Local0)

        Local0 = \PCI0.RP01.D38
        \PCI0.RP01.D38 = (Local0 ^ 0x5A)
        CHK ("PCI bridge: dword before the interrupt line",
             \PCI0.RP01.D38, Local0)

        Local0 = \PCI0.RP01.D3C
        \PCI0.RP01.D3C = (Local0 ^ 0x5A)
        CHK ("PCI bridge: interrupt line as a dword", \PCI0.RP01.D3C, Local0)

        Local0 = \PCI0.RP01.D44
        \PCI0.RP01.D44 = (Local0 ^ 0x5A)
        CHK ("PCI bridge: device-specific dword",
             \PCI0.RP01.D44, (Local0 ^ 0x5A))

        Local0 = \PCI0.CBUS.B04
        \PCI0.CBUS.B04 = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: command", \PCI0.CBUS.B04, Local0)

        Local0 = \PCI0.CBUS.B0C
        \PCI0.CBUS.B0C = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: cache line size", \PCI0.CBUS.B0C, Local0)

        Local0 = \PCI0.CBUS.B2B
        \PCI0.CBUS.B2B = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: last byte before the subsystem IDs",
             \PCI0.CBUS.B2B, Local0)

        Local0 = \PCI0.CBUS.B2C
        \PCI0.CBUS.B2C = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: subsystem vendor ID", \PCI0.CBUS.B2C, Local0)

        Local0 = \PCI0.CBUS.B2F
        \PCI0.CBUS.B2F = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: subsystem ID", \PCI0.CBUS.B2F, Local0)

        Local0 = \PCI0.CBUS.B30
        \PCI0.CBUS.B30 = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: expansion ROM", \PCI0.CBUS.B30, Local0)

        Local0 = \PCI0.CBUS.B3B
        \PCI0.CBUS.B3B = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: last byte before the interrupt line",
             \PCI0.CBUS.B3B, Local0)

        Local0 = \PCI0.CBUS.B3C
        \PCI0.CBUS.B3C = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: interrupt line", \PCI0.CBUS.B3C, Local0)

        Local0 = \PCI0.CBUS.B3F
        \PCI0.CBUS.B3F = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: max latency", \PCI0.CBUS.B3F, Local0)

        Local0 = \PCI0.CBUS.B44
        \PCI0.CBUS.B44 = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: device-specific byte",
             \PCI0.CBUS.B44, (Local0 ^ 0x5A))

        Local0 = \PCI0.CBUS.D10
        \PCI0.CBUS.D10 = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: BAR", \PCI0.CBUS.D10, Local0)

        Local0 = \PCI0.CBUS.D28
        \PCI0.CBUS.D28 = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: dword before the subsystem IDs",
             \PCI0.CBUS.D28, Local0)

        Local0 = \PCI0.CBUS.D2C
        \PCI0.CBUS.D2C = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: subsystem IDs as a dword", \PCI0.CBUS.D2C, Local0)

        Local0 = \PCI0.CBUS.D38
        \PCI0.CBUS.D38 = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: dword before the interrupt line",
             \PCI0.CBUS.D38, Local0)

        Local0 = \PCI0.CBUS.D3C
        \PCI0.CBUS.D3C = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: interrupt line as a dword",
             \PCI0.CBUS.D3C, Local0)

        Local0 = \PCI0.CBUS.D44
        \PCI0.CBUS.D44 = (Local0 ^ 0x5A)
        CHK ("CardBus bridge: device-specific dword",
             \PCI0.CBUS.D44, (Local0 ^ 0x5A))

        Return (FAIL)
    }
}
