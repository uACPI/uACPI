import os
import subprocess
from typing import List, Optional, Union


class ASL:
    @staticmethod
    def definition_block(kind: str, revision: int) -> str:
        block = "DefinitionBlock "
        block += f'("", "{kind}", {revision}, '
        block += '"uTEST", "TESTTABL", 0xF0F0F0F0)'

        return block

    @staticmethod
    def name(name: str, term_arg: Union[str, int]) -> str:
        return f"Name({name}, {term_arg})"

    @staticmethod
    def buffer(
        initializers: Optional[List[int]] = None,
        count: Optional[int] = None
    ) -> str:
        if count is not None:
            buf_len = count
        elif initializers is not None:
            buf_len = len(initializers)
        else:
            buf_len = 0

        buf = f"Buffer({buf_len})"

        buf += " { "
        if initializers is not None:
            buf += ", ".join([str(x) for x in initializers])
        buf += " }"

        return buf

    @staticmethod
    def method(name: str, num_args: Optional[int] = None) -> str:
        method = f"Method ({name}"
        if num_args is not None:
            method += f", {num_args}"
        method += ")"

        return method

    @staticmethod
    def invoke(name: str, args: List[str] = []) -> str:
        invocation = f"{name}("
        invocation += ", ".join(args)
        invocation += ")"
        return invocation

    @staticmethod
    def end_block() -> str:
        return "}"

    @staticmethod
    def assign(dst: str, src: str) -> str:
        return f"{dst} = {src}"

    @staticmethod
    def increment(name: str) -> str:
        return f"{name}++"

    @staticmethod
    def create_field(buf: str, idx: int, field_size: int,
                     field_name: str) -> str:
        return f"CreateField({buf}, {idx}, {field_size}, {field_name})"

    @staticmethod
    def iff(arg: str) -> str:
        return f"If ({arg})"

    @staticmethod
    def elsee() -> str:
        return "Else"

    @staticmethod
    def equal(arg0: str, arg1: str) -> str:
        return f"{arg0} == {arg1}"

    @staticmethod
    def returnn(arg: str) -> str:
        return f"Return ({arg})"


class ASLSource:
    def __init__(self, revision: int = 0):
        self.lines: List[str] = []
        self.revision = revision
        self.indentation = 0

        self.l(ASL.definition_block("DSDT", 2))
        self.block_begin()

    def l(self, line: str) -> None:
        line = " " * (self.indentation * 4) + line
        self.lines.append(line)

    def block_begin(self) -> None:
        self.l("{")
        self.indentation += 1

    def block_end(self) -> None:
        self.indentation -= 1
        self.l("}\n")

    def iff(self, arg: str) -> None:
        self.l(ASL.iff(arg) + " {")
        self.indentation += 1

    def elsee(self) -> None:
        self.indentation -= 1
        self.l("} Else {")
        self.indentation += 1

    def finalize(self) -> None:
        self.block_end()

    def dump(self, path: str) -> None:
        with open(path, "w") as f:
            f.write("\n".join(self.lines))

    def dump_as_test_case(
        self, path: str, case_name: str,
        expected_type: str, expected_value: Union[str, int]
    ) -> None:
        with open(path, "w") as f:
            f.write(f"// Name: (generated) {case_name}\n")
            f.write(f"// Expect: {expected_type} => {expected_value}\n")
            f.write("\n".join(self.lines))

    @staticmethod
    def compile(path: str, compiler: str, bin_dir: str) -> str:
        case_aml_name = os.path.basename(path).rsplit(".", 1)[0] + ".aml"
        out_case = os.path.join(bin_dir, case_aml_name)

        ignored_warnings = [
            # Warning 3144 Method Local is set but never used
            "-vw", "3144",
            # Remark 2098 Recursive method call
            "-vw", "2098",

            # Invalid type [Reference] found, RefOf operator requires
            # [Integer|String|Buffer|Package|FieldUnit|Device|Event|
            #  Method|Mutex|Region|Power|Processor|Thermal|BufferField|
            #  DdbHandle|DebugObject]
            "-vw", "6058",

            # One or more objects within the Pathname do not exist
            "-vw", "6161",
            # Too few arguments
            "-vw", "6005",
            # Called method returns no value
            "-vw", "6080",
            # Object does not exist
            "-vw", "6084",

            # Not a control method, cannot invoke
            "-vw", "6086",

            # Object is not referenced
            "-vw", "2089",

            # Creation of named objects within a method is highly inefficient
            "-vw", "2173",

            # Existing object has invalid type for Scope operator
            "-vw", "6117",

            # Switch expression is not a static Integer/Buffer/String data
            "-vw", "3124",

            # Static OperationRegion should be declared outside control method
            "-vw", "3175",

            # Missing dependency
            # (for some reason it has two different error codes)
            "-vw", "3141",
            "-vw", "6141",

            # Field Unit extends beyond region limit
            "-vw", "6031",

            # Name already exists in scope
            "-vw", "6074",

            # Object not found or not accessible from current scope
            "-vw", "6085",

            # Legacy Processor() keyword detected. Use Device() keyword instead
            "-vw", "3168",

            #  Local or Arg used outside a control method
            "-vw", "2067",
        ]

        args = [compiler, *ignored_warnings, "-oa", "-p", out_case, path]
        proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True)

        proc.wait(10)

        stdout = proc.stdout
        assert stdout
        stderr = proc.stderr
        assert stderr

        if proc.returncode != 0:
            raise RuntimeError(f"Compiler error:\nstdout:\n{stdout.read()}"
                               f"\nstderr:\n{stderr.read()}")

        return out_case
