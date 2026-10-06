// Name: Access to protected IO ports is filtered
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

    // The PIC, protected at all times
    OperationRegion (PIC, SystemIO, 0x1E, 4)
    Field (PIC, ByteAcc, NoLock) {
        Offset (2),
        P020, 8,
        P021, 8,
    }
    Field (PIC, WordAcc, NoLock) {
        Offset (2),
        W020, 16,
    }
    Field (PIC, DWordAcc, NoLock) {
        D01E, 32,
    }

    // RTC, only protected after an _OSI query for Windows XP or newer
    OperationRegion (RTC, SystemIO, 0x6E, 6)
    Field (RTC, ByteAcc, NoLock) {
        P06E, 8,
        P06F, 8,
        P070, 8,
        P071, 8,
        P072, 8,
        P073, 8,
    }
    Field (RTC, DWordAcc, NoLock) {
        D06E, 32,
    }

    // The last DMA port & whatever is after it
    OperationRegion (DMA, SystemIO, 0x0F, 2)
    Field (DMA, ByteAcc, NoLock) {
        P00F, 8,
        P010, 8,
    }
    Field (DMA, WordAcc, NoLock) {
        W00F, 16,
    }

    // POST codes, with the first DMA page register right after
    OperationRegion (POST, SystemIO, 0x80, 2)
    Field (POST, ByteAcc, NoLock) {
        P080, 8,
        P081, 8,
    }
    Field (POST, WordAcc, NoLock) {
        W080, 16,
    }

    // PCI configuration mechanism #1, protected at all times as well
    OperationRegion (PCIC, SystemIO, 0xCF8, 8)
    Field (PCIC, DWordAcc, NoLock) {
        PCIA, 32,
        PCID, 32,
    }

    Method (MAIN, 0, NotSerialized)
    {
        // Skip for non-uACPI test runners
        If (!_OSI ("TestRunner")) {
            Return (0)
        }

        /*
         * Only the first port of an access is checked, so an access that
         * starts before a protected port goes through as a whole. Use that
         * to see what the protected ports really contain.
         */
        D01E = 0x11223344
        CHK ("dword that runs into the PIC", D01E, 0x11223344)

        P020 = 0xA5
        P021 = 0xA5
        W020 = 0xA5A5
        CHK ("PIC after writes", D01E, 0x11223344)
        CHK ("PIC command port", P020, 0)
        CHK ("PIC data port", P021, 0)
        CHK ("PIC as a word", W020, 0)

        PCIA = 0x80000000
        PCID = 0xA5A5A5A5
        CHK ("PCI config address", PCIA, 0)
        CHK ("PCI config data", PCID, 0)

        // Nobody has asked about Windows XP yet, so the RTC is accessible
        D06E = 0xAABBCCDD
        CHK ("RTC index before _OSI", P070, 0xBB)
        P071 = 0x5A
        CHK ("RTC data before _OSI", P071, 0x5A)
        CHK ("RTC as a dword before _OSI", D06E, 0x5ABBCCDD)

        // Any older version doesn't count
        Local0 = _OSI ("Windows 2000")
        CHK ("RTC index after _OSI for Windows 2000", P070, 0xBB)

        // Anything newer than XP does
        Local0 = _OSI ("Windows 2015")
        CHK ("RTC index after _OSI", P070, 0)
        CHK ("RTC data after _OSI", P071, 0)
        P070 = 0x33
        P071 = 0x33
        CHK ("RTC after writes", D06E, 0x5ABBCCDD)

        // Its neighbours are not affected
        CHK ("port before the RTC", P06F, 0xCC)
        P072 = 0x77
        CHK ("port after the RTC", P072, 0x77)

        // An access that starts at a protected port is denied as a whole
        P010 = 0x77
        W00F = 0xFFFF
        CHK ("word that starts at a DMA port", W00F, 0)
        CHK ("port after the DMA ports", P010, 0x77)

        // And one that only runs into it is not
        W080 = 0x1234
        CHK ("word that runs into a DMA page register", W080, 0x1234)
        CHK ("POST code port", P080, 0x34)
        CHK ("DMA page register", P081, 0)

        Return (FAIL)
    }
}
