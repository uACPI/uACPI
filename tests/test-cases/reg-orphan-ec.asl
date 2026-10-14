// Name: _REG of an EC that has no EmbeddedControl regions is executed
// Expect: int => 0

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    // Only ever accessed via SystemMemory, which is common in practice
    Device (EC0) {
        Name (_HID, EisaId ("PNP0C09"))

        OperationRegion (ECMM, SystemMemory, 0x1000, 0x10)
        Name (CONS, 0)

        Method (_REG, 2) {
            If (Arg0 == 3 && Arg1 == 1) {
                CONS++
            }
        }
    }

    // Has a region of its own, so its _REG is executed for that one alone
    Device (EC1) {
        Name (_HID, EisaId ("PNP0C09"))

        OperationRegion (ECOR, EmbeddedControl, 0, 0x10)
        Name (CONS, 0)

        Method (_REG, 2) {
            If (Arg0 == 3 && Arg1 == 1) {
                CONS++
            }
        }
    }

    // Same as EC0, but an EC by its _CID
    Device (EC2) {
        Name (_HID, "UTST0001")
        Name (_CID, EisaId ("PNP0C09"))

        Name (CONS, 0)

        Method (_REG, 2) {
            If (Arg0 == 3 && Arg1 == 1) {
                CONS++
            }
        }
    }

    // Not an EC, so this is never executed for the EmbeddedControl space
    Device (NEC0) {
        Name (_HID, EisaId ("PNP0C0A"))

        Name (CONS, 0)

        Method (_REG, 2) {
            If (Arg0 == 3) {
                CONS++
            }
        }
    }

    Device (PCI0) {
        Name (_HID, EisaId ("PNP0A08"))

        Device (LPCB) {
            Name (_ADR, 0x001F0000)

            // Same as EC0, but further down the namespace
            Device (EC3) {
                Name (_HID, EisaId ("PNP0C09"))

                Name (CONS, 0)

                Method (_REG, 2) {
                    If (Arg0 == 3 && Arg1 == 1) {
                        CONS++
                    }
                }
            }
        }
    }

    Method (CHEK, 3) {
        If (Arg0 != Arg1) {
            Printf("%o: expected %o connect(s), got %o", Arg2, Arg1, Arg0)
            Return (1)
        }

        Return (0)
    }

    Method (MAIN) {
        Local0 = CHEK (\EC0.CONS, 1, "EC0")
        Local0 |= CHEK (\EC1.CONS, 1, "EC1")
        Local0 |= CHEK (\EC2.CONS, 1, "EC2")
        Local0 |= CHEK (\NEC0.CONS, 0, "NEC0")
        Local0 |= CHEK (\PCI0.LPCB.EC3.CONS, 1, "EC3")

        Return (Local0)
    }
}
