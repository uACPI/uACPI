// Name: Support for various address spaces works
// Expect: str => check-address-spaces-work

DefinitionBlock ("x.aml", "SSDT", 1, "uTEST", "ASPTESTS", 0xF0F0F0F0)
{
    Method (MAIN) {
        // Skip for non-uacpi test runners
        Return ("check-address-spaces-work")
    }

    Method (DOIP, 1, Serialized) {
        If (Arg0 == 0) {
            Local0 = "DEADBEE0"
            Local1 = 0xDEADBEE0
        } Else {
            Local0 = "DEADBEEF"
            Local1 = 0xDEADBEEF
        }

        OperationRegion (IPMR, IPMI, 0xDEADBEE0, 10)
        Field (IPMR, BufferAcc, NoLock, Preserve) {
            CMD0, 120,

            // Offset = base + 0xF
            CMD1, 1234,
        }

        Name (REQ, Buffer (32) { })
        Name (RET, 0)

        REQ = Concatenate("IPMICommand", Local0)

        If (Arg0 == 0) {
            Local0 = CMD0 = REQ
        } Else {
            Local0 = CMD1 = REQ
        }

        If (SizeOf(Local0) != 66) {
            Printf("Unexpected IPMI response size %o", SizeOf(Local0))
            Return (Zero)
        }

        RET = Local0
        If (RET != Local1) {
            Printf("Unexpected IMPI response %o, expected %o", RET, Local1)
            Return (Zero)
        }

        Return (Ones)
    }

    Device (GPO0)
    {
        Name (_HID, "INT33FC" /* Intel Baytrail GPIO Controller */)
        Name (_DDN, "ValleyView General Purpose Input/Output (GPIO) controller")
        Name (_UID, 0)
    }

    Device (GPO1)
    {
        Name (_HID, "INT33FC" /* Intel Baytrail GPIO Controller */)
        Name (_DDN, "ValleyView GPNCORE controller")
        Name (_UID, 1)
    }

    Method (DGIO, 0, Serialized) {
        OperationRegion (GPOP, GeneralPurposeIo, Zero, 0x06)
        Field (GPOP, ByteAcc, NoLock, Preserve)
        {
            Connection (
                GpioIo (Exclusive, PullDefault, 0x0000, 0x0000, IoRestrictionOutputOnly,
                    "\\GPO0", 0x00, ResourceConsumer, ,
                    )
                    {   // Pin list
                        0x0002, 0x0003, 0x0004, 0x0005, 0x0006
                    }
            ),
            CCU0,   1,
            CCU1,   3,
            CCU2,   1,
            Connection (
                GpioIo (Exclusive, PullDefault, 0x0000, 0x0000, IoRestrictionOutputOnly,
                    "\\GPO1", 0x00, ResourceConsumer, ,
                    )
                    {   // Pin list
                        0x005F
                    }
            ),
            CCU3,   1
        }

        CCU0 = 1
        CCU1 = 2
        CCU2 = 0

        Local0 = CCU0
        If (Local0 != 1) {
            Printf("Bad CCU0 return %o", Local0)
            Return (Zero)
        }

        Local0 = CCU1
        If (Local0 != 2) {
            Printf ("Bad CCU1 return %o", Local0)
            Return (Zero)
        }

        Local0 = CCU2
        If (Local0 != 0) {
            Printf ("Bad CCU2 return %o", Local0)
            Return (Zero)
        }

        Local0 = CCU3
        if (Local0 != 0) {
            Printf ("Bad CCU3 value %o", Local0)
            Return (Zero)
        }

        Return (Ones)
    }

    Method (DPCC, 0, Serialized) {
        OperationRegion (GPOP, PCC, 0xCA, 0xFF)
        Field (GPOP, DWordAcc, NoLock, Preserve)
        {
            H, 8,
            E, 8,
            L0, 8,
            L1, 8,
            O, 8,
            Offset(12),
            CMD, 32,
        }

        Field (GPOP, DWordAcc, NoLock, Preserve)
        {
            HELL, 48,
        }

        H = "H"
        E = "E"
        L0 = "L"
        L1 = "L"
        O = "O"

        If (ToString(HELL) != "HELLO") {
            Printf ("Unexpected HELL value %o", ToString(HELL))
            Return (Zero)
        }

        // Invoke the test runner handler
        CMD = 0xDEADBEEF

        // We expect it to modify the CMD field as a response
        If (CMD != 0xBEEFDEAD) {
            Printf ("Unexpected CMD value %o", CMD)
            Return (Zero)
        }

        Return (Ones)
    }

    Method (DPRM, 0, Serialized) {
        OperationRegion (GPOP, PlatformRtMechanism, 0x00, 0xFF)
        Field (GPOP, BufferAcc, NoLock, Preserve)
        {
            DEAD, 80,
        }

        Local0 = DEAD = "helloworld"
        Printf("Got a PRM response: %o", Local0)

        If (SizeOf(Local0) != 26) {
            Printf ("Unexpected Local0 size %o", SizeOf(Local0))
            Return (Zero)
        }

        If (ToString(Local0) != "goodbyeworld") {
            Printf ("Unexpected Local0 value %o", ToString(Local0))
            Return (Zero)
        }

        Return (Ones)
    }


    Method (DFHW, 0, Serialized) {
        OperationRegion (GPOP, FFixedHW, 0xCAFEBABE, 0xFEFECACA)
        Field (GPOP, BufferAcc, NoLock, Preserve)
        {
            X, 1,
        }

        Local0 = X = "someguidandstuff"
        Printf("Got a FFixedHW response: %o", Local0)

        If (SizeOf(Local0) != 256) {
            Printf ("Unexpected Local0 size %o", SizeOf(Local0))
            Return (Zero)
        }

        If (ToString(Local0) != "ok") {
            Printf ("Unexpected Local0 value %o", ToString(Local0))
            Return (Zero)
        }

        Return (Ones)
    }

    Scope (_SB) {
        Device (I2C0)
        {
            Name (_HID, "INT34B2")
            Name (_UID, 0)
        }

        Device (I2C1)
        {
            Name (_HID, "80860F41" /* Intel Baytrail I2C Host Controller */)
            Name (_CID, "80860F41" /* Intel Baytrail I2C Host Controller */)
            Name (_DDN, "Intel(R) I2C Controller #5 - 80860F45")
            Name (_UID, 1)
        }
    }

    Name (RES1, ResourceTemplate ()
    {
        I2cSerialBusV2 (0x0008, ControllerInitiated, 0x00061A80,
            AddressingMode7Bit, "\\_SB.I2C0",
            0x00, ResourceConsumer, , Exclusive,
            )
    })
    Name (RES2, ResourceTemplate ()
    {
        I2cSerialBusV2 (0x0040, ControllerInitiated, 0x00061A80,
            AddressingMode7Bit, "\\_SB.I2C1",
            0x00, ResourceConsumer, , Exclusive,
            )
    })

    Method (DGSB, 0, Serialized) {
        Method (CHEK, 3) {
            If (SizeOf(Arg0) != Arg1) {
                Printf(
                    "Bad resulting buffer length %o, expected %o",
                    SizeOf(Arg0), Arg1
                )

                Return (Zero)
            }

            Name (INT, 0)
            INT = Arg0

            If (INT != Arg2) {
                Printf("Unexpected response %o, expected %o", INT, Arg2)
                Return (Zero)
            }

            Return (Ones)
        }


        OperationRegion (RCH1, GenericSerialBus, 0x100, 0x0100)
        Field (RCH1, BufferAcc, NoLock, Preserve)
        {
            Connection (RES1),
            Offset (0x11),

            // Command == 0x111
            AccessAs (BufferAcc, AttribQuick),
            CMD0, 128,

            // Command == 0x121
            AccessAs (BufferAcc, AttribSendReceive),
            CMD1, 8,

            // Command == 0x122
            AccessAs (BufferAcc, AttribByte),
            CMD2, 16,

            // Command == 0x124
            AccessAs (BufferAcc, AttribWord),
            CMD3, 32,

            // Command == 0x128
            AccessAs (BufferAcc, AttribBlock),
            CMD4, 2048,

            // Command == 0x228
            AccessAs (BufferAcc, AttribProcessCall),
            CMD5, 8,

            // Command == 0x229
            AccessAs (BufferAcc, AttribBlockProcessCall),
            CMD6, 144,

            Connection (RES2),

            // Command == 0x23B
            AccessAs (BufferAcc, AttribBytes(15)),
            CMD7, 8,

            // Command == 0x23C
            AccessAs (BufferAcc, AttribRawBytes(255)),
            CMD8, 8,

            // Command == 0x23D
            AccessAs (BufferAcc, AttribRawProcessBytes(123)),
            CMD9, 8,
        }

        Local0 = CMD0 = 0x111
        If (CHEK(Local0, 2, 0x112) != Ones) {
            Return (Zero)
        }

        Local0 = 0x121
        Local0 = CMD1 = Local0
        If (CHEK(Local0, 3, 0x122) != Ones) {
            Return (Zero)
        }

        Local0 = CMD2 = 0x122
        If (CHEK(Local0, 3, 0x123) != Ones) {
            Return (Zero)
        }

        Local0 = CMD3
        If (CHEK(Local0, 4, 0x125) != Ones) {
            Return (Zero)
        }

        Local0 = CMD4
        If (CHEK(Local0, 257, 0x129) != Ones) {
            Return (Zero)
        }

        Local0 = CMD5 = 0x228
        If (CHEK(Local0, 4, 0x229) != Ones) {
            Return (Zero)
        }

        Local0 = CMD6
        If (CHEK(Local0, 257, 0x22A) != Ones) {
            Return (Zero)
        }

        Local0 = CMD7 = 0x23B
        If (CHEK(Local0, 15 + 2, 0x23C) != Ones) {
            Return (Zero)
        }

        Local0 = CMD8
        If (CHEK(Local0, 255 + 2, 0x23D) != Ones) {
            Return (Zero)
        }

        Local0 = CMD9
        If (CHEK(Local0, 255 + 2, 0x23E) != Ones) {
            Return (Zero)
        }

        Return (Ones)
    }

    /*
     * The handler of this address space evaluates the DTCH method of the
     * device that a region belongs to every time that the region is detached.
     * Both of these get rid of the region in response.
     */
    Device (OEM0) {
        Name (_HID, "TEST0001")

        OperationRegion (REG0, 0x80, 0, 1)
        Field (REG0, ByteAcc, NoLock, Preserve) {
            FLD0, 8,
        }

        Name (DISS, 0)

        Method (_REG, 2) {
            If (Arg1 == 0) {
                DISS++
            }
        }

        Method (DTCH) {
            CopyObject (Zero, REG0)
        }
    }

    Device (OEM1) {
        Name (_HID, "TEST0002")

        OperationRegion (REG1, 0x80, 0, 1)
        Field (REG1, ByteAcc, NoLock, Preserve) {
            FLD1, 8,
        }

        Method (DTCH) {
            CopyObject (Zero, REG1)
        }
    }

    Method (DOEM) {
        // Accessing a region is what gets it attached in the first place
        If (\OEM0.FLD0 != 0x5A || \OEM1.FLD1 != 0x5A) {
            Printf("Unexpected OEM field values")
            Return (Zero)
        }

        /*
         * A region is detached once it's overwritten, at which point REG0 is
         * overwritten by the DTCH method as well. This must not prevent the
         * rest from being done just once, and against the right object.
         */
        CopyObject (One, \OEM0.REG0)

        If (\OEM0.DISS != 1) {
            Printf("Unexpected number of _REG disconnects %o", \OEM0.DISS)
            Return (Zero)
        }

        If (\OEM0.REG0 != One) {
            Printf("REG0 was not overwritten: %o", \OEM0.REG0)
            Return (Zero)
        }

        Return (Ones)
    }

    /*
     * To be evaluated after OEM1 was given a handler of its own, which is what
     * detaches REG1 from the one that it had before.
     *
     * Return -> Ones on success, Zero on failure
     */
    Method (COEM) {
        If (ObjectType (\OEM1.REG1) != 1) {
            Printf("REG1 was not overwritten: %o", ObjectType (\OEM1.REG1))
            Return (Zero)
        }

        Return (Ones)
    }

    /*
     * Arg0 -> The address space type
     * Return -> Ones on succeess, Zero on failure
     */
    Method (CHEK, 1, Serialized) {
        Switch (Arg0) {
        Case (7) { // IPMI
            Local0 = DOIP(0)
            If (Local0 != Ones) {
                Break
            }

            Local0 = DOIP(1)
            Break
        }
        Case (8) { // General Purpose IO
            Local0 = DGIO()
            Break
        }
        Case (9) { // Generic Serial Bus
            Local0 = DGSB()
            Break
        }
        Case (0x0A) { // PCC
            Local0 = DPCC()
            Break
        }
        Case (0x0B) { // PRM
            Local0 = DPRM()
            Break
        }
        Case (0x7F) { // FFixedHW
            Local0 = DFHW()
            Break
        }
        Case (0x80) { // The first one of the OEM defined address spaces
            Local0 = DOEM()
            Break
        }
        }

        If (Local0 != Ones) {
            Printf("Address space %o failed: expected '%o', got '%o'!",
                   Arg0, Ones, Local0)
            Return (Zero)
        }

        Printf("Address space %o OK", ToHexString(Arg0))
        Return (Ones)
    }

    /*
     * Unlike the IPMI region above, this one is not created by a method, and
     * thus gets to have a _REG method.
     */
    Device (IPMD) {
        Name (_HID, "TEST0000")

        OperationRegion (IPMS, IPMI, 0, 1)

        // Whether the region is connected, as far as _REG is aware
        Name (CONN, 0xFF)

        Method (_REG, 2) {
            If (Arg0 == 7) {
                CONN = Arg1
            }
        }
    }

    /*
     * Arg0 -> Whether IPMS is expected to be connected
     * Return -> Ones on success, Zero on failure
     */
    Method (CREG, 1) {
        If (\IPMD.CONN != Arg0) {
            Printf("Unexpected IPMS connection state %o, expected %o",
                   \IPMD.CONN, Arg0)
            Return (Zero)
        }

        Return (Ones)
    }

    // Same as IPMD, but ends up with an IPMI handler of its own
    Device (IPM2) {
        Name (_HID, "TEST0003")

        OperationRegion (IPS2, IPMI, 0, 1)

        Name (CONN, 0xFF)

        Method (_REG, 2) {
            If (Arg0 == 7) {
                CONN = Arg1
            }
        }
    }

    /*
     * Arg0 -> Whether IPS2 is expected to be connected
     * Return -> Ones on success, Zero on failure
     */
    Method (CRG2, 1) {
        If (\IPM2.CONN != Arg0) {
            Printf("Unexpected IPS2 connection state %o, expected %o",
                   \IPM2.CONN, Arg0)
            Return (Zero)
        }

        Return (Ones)
    }
}
