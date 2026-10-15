import os
import copy
import subprocess
from typing import List, Optional, Callable
from utilities.asl import ASL, ASLSource


ACPICA_BUFFER_PRINT_PREFIX = "    0000: "


def _parse_acpiexec_buffers(raw_output: str) -> List[List[int]]:
    lines = raw_output.split("\n")
    answers = []

    for i, line in enumerate(lines):
        if "Evaluating" in line:
            lines = lines[i + 1:]
            break

    for line in lines:
        if not line.startswith(ACPICA_BUFFER_PRINT_PREFIX):
            continue

        line = line.removeprefix(ACPICA_BUFFER_PRINT_PREFIX)
        buffer_bytes = []

        for x in line.split(" "):
            # Buffers are printed out with ascii disassembly at the end.
            # Skip as soon as we encounter empty space.
            if x == "":
                break

            buffer_bytes.append(int(x, base=16))

        answers.append(buffer_bytes)

    return answers


def _generate_for_each_bit_combination(
    src: ASLSource, per_combo_cb: Callable,
    final_cb: Optional[Callable] = None
) -> None:
    methods = []

    for i in range(0, 64):
        method_name = f"FT{i}"
        methods.append(method_name)

        src.l(ASL.method(method_name))
        src.block_begin()

        for j in range(0, 65):
            if (i >= j):
                continue

            per_combo_cb(i, j, src)

        src.block_end()

    src.l(ASL.method("MAIN"))
    src.block_begin()
    for method in methods:
        src.l(ASL.invoke(method))

    if final_cb is not None:
        final_cb(src)

    src.block_end()
    src.finalize()


_READS_ANSWERS_NAME = "buffer-reads-answers"
_WRITES_ANSWERS_NAME = "buffer-writes-answers"


def _generate_buffer_reads_answers(
    compiler: str, bin_dir: str, src: ASLSource
) -> List[List[int]]:
    output_path = os.path.join(bin_dir, _READS_ANSWERS_NAME + ".aml")
    if not os.path.exists(output_path):
        _do_generate_buffer_reads_answers(compiler, bin_dir, src)

    raw_answers = subprocess.check_output(
        ["acpiexec", "-b", "execute MAIN", output_path],
        universal_newlines=True
    )
    return _parse_acpiexec_buffers(raw_answers)


def _generate_buffer_writes_answers(
    compiler: str, bin_dir: str, src: ASLSource
) -> List[List[int]]:
    output_path = os.path.join(bin_dir, _WRITES_ANSWERS_NAME + ".aml")
    if not os.path.exists(output_path):
        _do_generate_buffer_writes_answers(compiler, bin_dir, src)

    raw_answers = subprocess.check_output(
        ["acpiexec", "-b", "execute MAIN", output_path],
        universal_newlines=True
    )
    return _parse_acpiexec_buffers(raw_answers)


def _do_generate_buffer_reads_answers(
    compiler: str, bin_dir: str, src: ASLSource
) -> None:
    def gen_buffer_dump(i, j, src):
        field_size = j - i
        field_name = f"FI{field_size:02X}"

        src.l(ASL.create_field("BUFF", i, field_size, field_name))
        src.l(ASL.assign("Debug", field_name))

    _generate_for_each_bit_combination(src, gen_buffer_dump)

    answers_src_path = os.path.join(bin_dir, _READS_ANSWERS_NAME + ".asl")
    src.dump(answers_src_path)
    ASLSource.compile(answers_src_path, compiler, bin_dir)


def _do_generate_buffer_writes_answers(
    compiler: str, bin_dir: str, src: ASLSource
) -> None:
    def gen_buffer_dump(i, j, src):
        field_size = j - i
        field_name = f"FI{field_size:02X}"

        src.l(ASL.create_field("BUFX", i, field_size, field_name))
        src.l(ASL.assign(field_name, _last_chunk_of_buff(field_size)))
        src.l(ASL.assign("Debug", field_name))

    _generate_for_each_bit_combination(src, gen_buffer_dump)

    writes_src_path = os.path.join(bin_dir, _WRITES_ANSWERS_NAME + ".asl")
    src.dump(writes_src_path)
    ASLSource.compile(writes_src_path, compiler, bin_dir)


_READS_TEST_NAME = "2080-buffer-reads"
_WRITES_TEST_NAME = "2080-buffer-writes"


def generate_buffer_reads_test(compiler: str, bin_dir: str) -> str:
    output_path = os.path.join(bin_dir, _READS_TEST_NAME + ".asl")
    if os.path.exists(output_path):
        return output_path

    return _do_generate_buffer_reads_test(compiler, bin_dir)


def generate_buffer_writes_test(compiler: str, bin_dir: str) -> str:
    output_path = os.path.join(bin_dir, _WRITES_TEST_NAME + ".asl")
    if os.path.exists(output_path):
        return output_path

    return _do_generate_buffer_writes_test(compiler, bin_dir)


_BUFF_BYTES = [0xAC, 0x12, 0x42, 0xCA, 0xDE, 0xFF, 0xCB, 0xDD]


def _last_chunk_of_buff(field_size: int) -> str:
    """
    NT stores a buffer to a buffer field one field-sized chunk at a time, so
    it's the last chunk that ends up in there. acpiexec truncates the buffer
    instead, so it only gets to see that chunk.
    """
    chunk_size = (field_size + 7) // 8
    offset = (len(_BUFF_BYTES) - 1) // chunk_size * chunk_size
    return ASL.buffer(_BUFF_BYTES[offset:])


def _generate_buffer_test_prologue() -> ASLSource:
    src = ASLSource(2)

    src.l(ASL.name("BUFF", ASL.buffer(_BUFF_BYTES)))
    src.l(ASL.name(
        "BUFX",
        ASL.buffer(count=8)
    ))

    return src


def _generate_buffer_test_harness(src: ASLSource) -> None:
    src.l(ASL.name("FAIL", 0))
    src.l(ASL.name("PASS", 0))

    src.l(ASL.method("FDBG", 3))
    src.block_begin()
    src.l(ASL.assign("Debug", "Arg0"))
    src.l(ASL.assign("Debug", "Arg1"))
    src.l(ASL.assign("Debug", "Arg2"))
    src.l(ASL.increment("FAIL"))
    src.block_end()


def _do_generate_buffer_reads_test(compiler: str, bin_dir: str) -> str:
    src = _generate_buffer_test_prologue()
    answers = _generate_buffer_reads_answers(compiler, bin_dir,
                                             copy.deepcopy(src))

    _generate_buffer_test_harness(src)

    answer_idx = 0

    def gen_buffer_check(i, j, src):
        nonlocal answer_idx
        field_size = j - i
        field_name = f"FI{field_size:02X}"

        src.l(ASL.create_field("BUFF", i, field_size, field_name))
        src.iff(ASL.equal(field_name, ASL.buffer(answers[answer_idx])))
        answer_idx += 1
        src.l(ASL.increment("PASS"))
        src.elsee()
        src.l(ASL.invoke("FDBG", [
            field_name, "__LINE__", f'"{field_name}"'
        ]))
        src.block_end()

    _generate_for_each_bit_combination(src, gen_buffer_check,
                                       lambda src: src.l(ASL.returnn("FAIL")))

    test_src_path = os.path.join(bin_dir, _READS_TEST_NAME + ".asl")
    src.dump_as_test_case(test_src_path, "Reads from buffer fields",
                          "int", "0")

    return test_src_path


def _do_generate_buffer_writes_test(compiler: str, bin_dir: str) -> str:
    src = _generate_buffer_test_prologue()
    answers = _generate_buffer_writes_answers(compiler, bin_dir,
                                              copy.deepcopy(src))

    _generate_buffer_test_harness(src)

    answer_idx = 0

    def gen_buffer_check(i, j, src):
        nonlocal answer_idx
        field_size = j - i
        field_name = f"FI{field_size:02X}"

        src.l(ASL.create_field("BUFX", i, field_size, field_name))
        src.l(ASL.assign(field_name, "BUFF"))
        src.iff(ASL.equal(field_name, ASL.buffer(answers[answer_idx])))
        answer_idx += 1
        src.l(ASL.increment("PASS"))
        src.elsee()
        src.l(ASL.invoke("FDBG", [
            field_name, "__LINE__", f'"{field_name}"'
        ]))
        src.block_end()
        src.l(ASL.assign("BUFX", 0))

    _generate_for_each_bit_combination(src, gen_buffer_check,
                                       lambda src: src.l(ASL.returnn("FAIL")))

    test_src_path = os.path.join(bin_dir, _WRITES_TEST_NAME + ".asl")
    src.dump_as_test_case(test_src_path, "Writes to buffer fields",
                          "int", "0")

    return test_src_path
