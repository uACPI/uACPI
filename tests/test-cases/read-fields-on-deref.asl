// Name: DerefOf reads field objects
// Expect: int => 255

DefinitionBlock ("", "DSDT", 2, "uTEST", "TESTTABL", 0xF0F0F0F0)
{
    Name (MAIN, 0xFF)

    OperationRegion(MYRE, SystemMemory, 0, 128)
    Field (MYRE, AnyAcc, NoLock) {
        FILD, 40
    }

    FILD = "Hello"

    Name (RES, "XXXXX")

    Method (CHEK, 1) {
        if (RES != Arg0) {
            Printf("Invalid value read: %o, expected %o", RES, Arg0)
            MAIN = 0
        }
    }

    // First try a simple one-level reference
    Local0 = RefOf(FILD)
    RES = DerefOf(Local0)
    CHEK("Hello")

    // Now try a nested three-level reference
    RES = "XXXXX"
    Local1 = RefOf(Local0)
    Local2 = RefOf(Local1)
    FILD = "World"
    RES = DerefOf(Local2)
    CHEK("World")
}
