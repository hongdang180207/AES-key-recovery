"""Shared I/O and solver adapters for AES key-recovery approaches."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .banning_solution import SolveResult, _parse_solver_output, read_cnf, write_cnf


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KISSAT = ROOT / "solvers" / "kissat" / "build" / "kissat"
DEFAULT_CMS = ROOT / "solvers" / "cryptominisat" / "build" / "cryptominisat5"


def read_xcnf(path: str | Path) -> tuple[int, list[list[int]], list[list[int]]]:
    """Read CryptoMiniSat DIMACS with ordinary and ``x ... 0`` clauses."""
    num_vars = declared = None
    clauses: list[list[int]] = []
    xors: list[list[int]] = []
    current: list[int] = []
    with Path(path).open("r", encoding="ascii") as stream:
        for line_no, raw in enumerate(stream, 1):
            line = raw.strip()
            if not line or line.startswith("c"):
                continue
            if line.startswith("p"):
                parts = line.split()
                if num_vars is not None or len(parts) != 4 or parts[1] != "cnf":
                    raise ValueError(f"Invalid/multiple XCNF header at line {line_no}")
                num_vars, declared = int(parts[2]), int(parts[3])
                continue
            if num_vars is None:
                raise ValueError(f"Clause before header at line {line_no}")
            if line.startswith("x"):
                if current:
                    raise ValueError(f"XOR line inside an unfinished clause at line {line_no}")
                tokens = line.split()
                if not tokens[0].startswith("x") or tokens[-1] != "0":
                    raise ValueError(f"Invalid XOR row at line {line_no}")
                equation = [int(tokens[0][1:])] + [int(token) for token in tokens[1:-1]]
                if not equation or any(lit == 0 or abs(lit) > num_vars for lit in equation):
                    raise ValueError(f"Invalid XOR literals at line {line_no}")
                xors.append(equation)
                continue
            for token in line.split():
                lit = int(token)
                if lit == 0:
                    clauses.append(current)
                    current = []
                else:
                    if abs(lit) > num_vars:
                        raise ValueError(f"Literal {lit} outside 1..{num_vars} at line {line_no}")
                    current.append(lit)
    if num_vars is None or declared is None:
        raise ValueError("Missing XCNF header")
    if current or declared != len(clauses) + len(xors):
        raise ValueError(f"XCNF declares {declared} constraints but has "
                         f"{len(clauses) + len(xors)} complete constraints")
    return num_vars, clauses, xors


def read_problem(path: str | Path, *, xor_format: bool = False):
    if xor_format:
        return read_xcnf(path)
    num_vars, clauses = read_cnf(path)
    return num_vars, clauses, []


def write_problem(path: str | Path, num_vars: int, clauses,
                  xor_equations=(), *, xor_format: bool = False) -> None:
    if not xor_format:
        if xor_equations:
            raise ValueError("XOR equations cannot be written as standard DIMACS")
        write_cnf(path, num_vars, clauses)
        return
    clauses, xor_equations = list(clauses), list(xor_equations)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="\n") as stream:
        stream.write(f"p cnf {num_vars} {len(clauses) + len(xor_equations)}\n")
        for clause in clauses:
            stream.write(" ".join(map(str, clause)) + " 0\n")
        for equation in xor_equations:
            stream.write("x" + str(equation[0]) + " "
                         + " ".join(map(str, equation[1:])) + " 0\n")


def solve_with_solver(cnf_path: str | Path, *, solver: str = "kissat",
                      solver_path: str | Path | None = None,
                      timeout: float | None = None, xor_format: bool = False,
                      threads: int = 1) -> SolveResult:
    """Call Kissat or CryptoMiniSat and parse SAT competition output."""
    solver = solver.lower()
    if solver not in {"kissat", "cryptominisat", "cms"}:
        raise ValueError("solver must be 'kissat' or 'cryptominisat'")
    if solver == "cms":
        solver = "cryptominisat"
    if xor_format and solver != "cryptominisat":
        raise ValueError("Native XOR DIMACS requires CryptoMiniSat; Kissat needs standard CNF")
    default = DEFAULT_KISSAT if solver == "kissat" else DEFAULT_CMS
    requested = str(solver_path or default)
    executable = str(Path(requested).resolve()) if Path(requested).is_file() else shutil.which(requested)
    if not executable:
        raise FileNotFoundError(f"{solver} executable not found: {requested}")
    cnf_path = str(Path(cnf_path).resolve())
    if solver == "kissat":
        command = [executable, cnf_path, "--relaxed", "-q"]
    else:
        command = [executable, "--verb", "0", "--threads", str(max(1, threads)), cnf_path]
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - started
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return SolveResult("TIMEOUT", None, elapsed, None, stdout, stderr)
    elapsed = time.perf_counter() - started
    return _parse_solver_output(completed.stdout, completed.stderr, completed.returncode, elapsed)


def result_paths(name: str, approach: str) -> tuple[Path, Path]:
    safe_name = Path(name).stem.replace(" ", "_")
    return (ROOT / "results" / "solutions" / f"{approach}_{safe_name}.jsonl",
            ROOT / "results" / "timings" / f"{approach}_{safe_name}.json")


def write_summary(path: str | Path, payload: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    full = dict(payload)
    full.setdefault("finished_at_utc", datetime.now(timezone.utc).isoformat())
    path.write_text(json.dumps(full, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_key_record(stream, index: int, key_hex: str, elapsed: float,
                     solver_elapsed: float, **metadata) -> None:
    record = {"index": index, "key_hex": key_hex,
              "elapsed_seconds": elapsed, "solver_call_seconds": solver_elapsed}
    record.update(metadata)
    stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    stream.flush()


def key_variables_from_round(round_index: int, bit_indices: Sequence[int]) -> list[int]:
    """Map AES-128 round-key bit offsets to the thesis generator's variable IDs."""
    if not 0 <= round_index <= 10:
        raise ValueError("round index must be in 0..10")
    if any(not 0 <= bit < 128 for bit in bit_indices):
        raise ValueError("round-key bit offsets must be in 0..127")
    base = 1 if round_index == 0 else 161 + (round_index - 1) * 160
    return [base + bit for bit in bit_indices]


def read_schedule_unit_observations(path: str | Path, *, xor_format: bool = False
                                    ) -> dict[int, dict[int, int]]:
    """Return round-key bits fixed by unit clauses, using the thesis numbering."""
    num_vars, clauses, _ = read_problem(path, xor_format=xor_format)
    lookup = {variable: (round_index, bit_index)
              for round_index in range(11)
              for bit_index, variable in enumerate(key_variables_from_round(round_index, range(128)))}
    observations: dict[int, dict[int, int]] = {}
    for clause in clauses:
        if len(clause) != 1:
            continue
        literal = clause[0]
        if abs(literal) > num_vars or abs(literal) not in lookup:
            continue
        round_index, bit_index = lookup[abs(literal)]
        bit_value = int(literal > 0)
        previous = observations.setdefault(round_index, {}).get(bit_index)
        if previous is not None and previous != bit_value:
            raise ValueError(f"Conflicting observed unit for round {round_index} bit {bit_index}")
        observations[round_index][bit_index] = bit_value
    if not observations:
        raise ValueError("CNF contains no observed AES round-key bits as unit clauses")
    return observations


def validate_aes128_key(key_hex: str, observations: dict[int, dict[int, int]]) -> bool:
    """Validate a recovered master key against all fixed round-key bits."""
    try:
        from ..cnf.aeskeyschedule2 import key_schedule
    except ImportError:
        from src.cnf.aeskeyschedule2 import key_schedule
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        return False
    if len(key) != 16:
        return False
    schedule = key_schedule(key)
    for round_index, fixed in observations.items():
        word = int.from_bytes(schedule[round_index], "big")
        for bit_index, expected in fixed.items():
            if ((word >> (127 - bit_index)) & 1) != expected:
                return False
    return True


def thesis_instanced_variables(observations: dict[int, dict[int, int]], infer_bits: int) -> list[int]:
    """Select the appendix's split guess: bits after round-1 prefix and before round-10 suffix."""
    if not 0 <= infer_bits <= 128 or infer_bits % 2:
        raise ValueError("infer_bits must be an even number in 0..128")
    r1_prefix = 0
    while r1_prefix in observations.get(1, {}):
        r1_prefix += 1
    r10_suffix = 128
    while r10_suffix - 1 in observations.get(10, {}):
        r10_suffix -= 1
    half = infer_bits // 2
    if r1_prefix + half > 128 or r10_suffix - half < 0:
        raise ValueError("Not enough unobserved bits adjacent to the round-1/round-10 observations")
    return (key_variables_from_round(1, range(r1_prefix, r1_prefix + half))
            + key_variables_from_round(10, range(r10_suffix - half, r10_suffix)))


__all__ = ["DEFAULT_KISSAT", "DEFAULT_CMS", "read_cnf", "write_cnf",
           "read_xcnf", "read_problem", "write_problem",
           "solve_with_solver", "result_paths", "write_summary",
           "write_key_record", "key_variables_from_round",
           "read_schedule_unit_observations", "validate_aes128_key",
           "thesis_instanced_variables"]
