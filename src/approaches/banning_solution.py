"""Enumerate distinct AES-128 keys satisfying a DIMACS CNF with Kissat.

The thesis generator numbers the initial key bits 1..128, in the order used
to form the 128-bit binary key. The thesis' sign conversion maps a positive
model literal to key bit 1 and a negative literal to key bit 0.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KISSAT = PROJECT_ROOT / "solvers" / "kissat" / "build" / "kissat"
DEFAULT_WORK_DIR = PROJECT_ROOT / "results" / "logs"
DEFAULT_SOLUTION_DIR = PROJECT_ROOT / "results" / "solutions"
DEFAULT_TIMING_DIR = PROJECT_ROOT / "results" / "timings"


@dataclass
class SolveResult:
    status: str
    model: dict[int, bool] | None
    elapsed_seconds: float
    returncode: int | None
    stdout: str = ""
    stderr: str = ""


@dataclass
class EnumerationResult:
    input_file: str
    status: str
    solution_count: int
    elapsed_seconds: float
    solver_calls: int
    keys_hex: list[str]
    per_call_seconds: list[float]
    error: str | None = None


def read_cnf(path: str | Path) -> tuple[int, list[list[int]]]:
    """Read and validate DIMACS CNF, allowing clauses to span lines."""
    path = Path(path)
    num_vars: int | None = None
    declared_clauses: int | None = None
    clauses: list[list[int]] = []
    current: list[int] = []

    with path.open("r", encoding="ascii") as stream:
        for line_number, raw_line in enumerate(stream, 1):
            line = raw_line.strip()
            if not line or line.startswith("c"):
                continue
            if line.startswith("p"):
                if num_vars is not None or clauses or current:
                    raise ValueError(f"Multiple or misplaced DIMACS header at line {line_number}")
                parts = line.split()
                if len(parts) != 4 or parts[1] != "cnf":
                    raise ValueError(f"Invalid DIMACS header at line {line_number}")
                try:
                    num_vars, declared_clauses = int(parts[2]), int(parts[3])
                except ValueError as exc:
                    raise ValueError(f"Non-integer DIMACS header at line {line_number}") from exc
                if num_vars < 0 or declared_clauses < 0:
                    raise ValueError("DIMACS variable and clause counts must be non-negative")
                continue
            if num_vars is None:
                raise ValueError(f"Clause before DIMACS header at line {line_number}")

            for token in line.split():
                try:
                    literal = int(token)
                except ValueError as exc:
                    raise ValueError(f"Invalid literal {token!r} at line {line_number}") from exc
                if literal == 0:
                    clauses.append(current)
                    current = []
                else:
                    if abs(literal) > num_vars:
                        raise ValueError(f"Literal {literal} exceeds declared variable count {num_vars}")
                    current.append(literal)

    if num_vars is None or declared_clauses is None:
        raise ValueError("Missing DIMACS header")
    if current:
        raise ValueError("Last DIMACS clause is missing terminating 0")
    if len(clauses) != declared_clauses:
        raise ValueError(f"Header declares {declared_clauses} clauses, found {len(clauses)}")
    return num_vars, clauses


def write_cnf(path: str | Path, num_vars: int, clauses: Iterable[Sequence[int]]) -> None:
    """Write DIMACS CNF with a correct header and normalized clause lines."""
    normalized = [list(clause) for clause in clauses]
    if num_vars < 0:
        raise ValueError("num_vars must be non-negative")
    for clause in normalized:
        if any(lit == 0 or abs(lit) > num_vars for lit in clause):
            raise ValueError("Clause contains zero or a literal outside the declared variable range")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="\n") as stream:
        stream.write(f"p cnf {num_vars} {len(normalized)}\n")
        for clause in normalized:
            stream.write(" ".join(map(str, clause)) + " 0\n")


def _parse_solver_output(stdout: str, stderr: str, returncode: int, elapsed: float) -> SolveResult:
    """Parse standard SAT competition status and model lines."""
    status_lines = [line.strip()[2:].strip().upper() for line in (stdout + "\n" + stderr).splitlines()
                    if line.strip().lower().startswith("s ")]
    status = next((s for s in reversed(status_lines)
                   if s in {"SATISFIABLE", "UNSATISFIABLE", "UNKNOWN"}), None)
    if status == "UNSATISFIABLE" or returncode == 20:
        return SolveResult("UNSAT", None, elapsed, returncode, stdout, stderr)
    if status == "UNKNOWN" or returncode == 0 and status is None:
        return SolveResult("UNKNOWN", None, elapsed, returncode, stdout, stderr)
    if status != "SATISFIABLE" and returncode != 10:
        raise RuntimeError(f"Kissat failed (exit {returncode}). stdout:\n{stdout}\nstderr:\n{stderr}")

    model: dict[int, bool] = {}
    for line in (stdout + "\n" + stderr).splitlines():
        line = line.strip()
        if not line.lower().startswith("v "):
            continue
        for token in line.split()[1:]:
            try:
                literal = int(token)
            except ValueError as exc:
                raise RuntimeError(f"Invalid literal in Kissat model: {token!r}") from exc
            if literal == 0:
                continue
            variable, value = abs(literal), literal > 0
            if variable in model and model[variable] != value:
                raise RuntimeError(f"Contradictory assignments for variable {variable} in solver model")
            model[variable] = value
    if not model:
        raise RuntimeError(f"Kissat reported SAT without a model. stdout:\n{stdout}\nstderr:\n{stderr}")
    return SolveResult("SAT", model, elapsed, returncode, stdout, stderr)


def solve_with_kissat(cnf_path: str | Path, kissat: str | Path = DEFAULT_KISSAT,
                      timeout: float | None = None) -> SolveResult:
    """Run Kissat, distinguishing SAT, UNSAT, UNKNOWN and timeout."""
    executable = shutil.which(str(kissat)) if not Path(kissat).is_file() else str(Path(kissat).resolve())
    if not executable:
        raise FileNotFoundError(f"Kissat executable not found: {kissat}")
    command = [executable, str(Path(cnf_path).resolve()), "--relaxed", "-q"]
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - started
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return SolveResult("TIMEOUT", None, elapsed, None, stdout, stderr)
    elapsed = time.perf_counter() - started
    return _parse_solver_output(completed.stdout, completed.stderr, completed.returncode, elapsed)


def model_to_binary(model: dict[int, bool] | Sequence[int], key_variables: Sequence[int] | None = None) -> str:
    """Extract key bits; positive DIMACS model assignment means key bit 1."""
    key_variables = list(key_variables or range(1, 129))
    if len(key_variables) != 128 or len(set(key_variables)) != 128:
        raise ValueError("Exactly 128 distinct key variable IDs are required")
    if isinstance(model, dict):
        assignments = model
    else:
        assignments = {abs(lit): lit > 0 for lit in model}
    missing = [var for var in key_variables if var not in assignments]
    if missing:
        raise ValueError(f"SAT model omits key variables: {missing}")
    return "".join("1" if assignments[var] else "0" for var in key_variables)


def binary_to_hex(binary: str) -> str:
    if len(binary) != 128 or set(binary) - {"0", "1"}:
        raise ValueError("AES-128 key must contain exactly 128 binary digits")
    return f"{int(binary, 2):032x}"


def key_blocking_clause(model: dict[int, bool], key_variables: Sequence[int] | None = None) -> list[int]:
    """Exclude this key while leaving auxiliary SAT variables unconstrained."""
    key_variables = list(key_variables or range(1, 129))
    if len(key_variables) != 128 or len(set(key_variables)) != 128:
        raise ValueError("Exactly 128 distinct key variable IDs are required")
    missing = [var for var in key_variables if var not in model]
    if missing:
        raise ValueError(f"SAT model omits key variables needed for blocking: {missing}")
    # To forbid a true variable, include its negative literal, and vice versa.
    return [-var if model[var] else var for var in key_variables]


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def banning_solution(input_file: str | Path, *, kissat: str | Path = DEFAULT_KISSAT,
                     work_dir: str | Path = DEFAULT_WORK_DIR,
                     solution_dir: str | Path = DEFAULT_SOLUTION_DIR,
                     timing_dir: str | Path = DEFAULT_TIMING_DIR,
                     timeout: float | None = None, max_solutions: int | None = None,
                     key_variables: Sequence[int] | None = None,
                     solver: str = "kissat", solver_path: str | Path | None = None,
                     xor_format: bool = False, threads: int = 1) -> EnumerationResult:
    """Enumerate distinct AES-128 keys and persist machine-readable results."""
    input_file = Path(input_file).resolve()
    if not input_file.is_file():
        raise FileNotFoundError(input_file)
    if xor_format:
        from .common import read_problem
        num_vars, original_clauses, xor_equations = read_problem(input_file, xor_format=True)
    else:
        num_vars, original_clauses = read_cnf(input_file)
        xor_equations = []
    key_variables = list(key_variables or range(1, 129))
    if len(key_variables) != 128 or len(set(key_variables)) != 128:
        raise ValueError("Exactly 128 distinct key variable IDs are required")
    if min(key_variables) < 1 or max(key_variables) > num_vars:
        raise ValueError(f"Key variable IDs must be in 1..{num_vars}")

    work_dir, solution_dir, timing_dir = map(Path, (work_dir, solution_dir, timing_dir))
    work_dir.mkdir(parents=True, exist_ok=True)
    solution_dir.mkdir(parents=True, exist_ok=True)
    timing_dir.mkdir(parents=True, exist_ok=True)
    working_file = work_dir / f"{input_file.stem}_working.cnf"
    solutions_path = solution_dir / f"{input_file.stem}_solutions.jsonl"
    timing_path = timing_dir / f"{input_file.stem}_timing.json"
    clauses = list(original_clauses)
    keys: list[str] = []
    call_times: list[float] = []
    solver_calls = 0
    started = time.perf_counter()
    status = "ERROR"
    error: str | None = None

    try:
        with solutions_path.open("w", encoding="utf-8", newline="\n") as output:
            while max_solutions is None or len(keys) < max_solutions:
                if xor_format:
                    from .common import write_problem
                    write_problem(working_file, num_vars, clauses, xor_equations,
                                  xor_format=True)
                else:
                    write_cnf(working_file, num_vars, clauses)
                print(f"  solver call {solver_calls + 1}: {len(keys)} distinct key(s) so far",
                      flush=True)
                if solver == "kissat" and not xor_format and solver_path is None:
                    solved = solve_with_kissat(working_file, kissat=kissat, timeout=timeout)
                else:
                    from .common import solve_with_solver
                    solved = solve_with_solver(working_file, solver=solver,
                                               solver_path=solver_path or (kissat if solver == "kissat" else None),
                                               timeout=timeout, xor_format=xor_format,
                                               threads=threads)
                solver_calls += 1
                call_times.append(solved.elapsed_seconds)
                print(f"  call {solver_calls}: {solved.status} in {solved.elapsed_seconds:.2f}s",
                      flush=True)
                if solved.status != "SAT":
                    status = solved.status
                    break
                assert solved.model is not None
                key_hex = binary_to_hex(model_to_binary(solved.model, key_variables))
                if key_hex in keys:
                    raise RuntimeError(f"Solver returned duplicate key despite key blocking: {key_hex}")
                keys.append(key_hex)
                output.write(json.dumps({
                    "index": len(keys), "key_hex": key_hex,
                    "elapsed_seconds": time.perf_counter() - started,
                    "solver_call_seconds": solved.elapsed_seconds,
                }) + "\n")
                output.flush()
                print(f"  key {len(keys)}: {key_hex}", flush=True)
                clauses.append(key_blocking_clause(solved.model, key_variables))
            else:
                status = "LIMIT_REACHED"
    except Exception as exc:
        status = "ERROR"
        error = f"{type(exc).__name__}: {exc}"
    except KeyboardInterrupt:
        status = "INTERRUPTED"
        error = "Interrupted by user; keys found so far are preserved."
    finally:
        elapsed = time.perf_counter() - started
        working_file.unlink(missing_ok=True)

    result = EnumerationResult(str(input_file), status, len(keys), elapsed, solver_calls,
                               keys, call_times, error)
    payload = asdict(result)
    payload["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    payload["timeout_per_solver_call_seconds"] = timeout
    payload["max_solutions"] = max_solutions
    payload["key_variables"] = key_variables
    _write_json(timing_path, payload)
    if error and status == "ERROR":
        raise RuntimeError(error)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cnf", nargs="+", type=Path, help="Input DIMACS CNF file(s)")
    parser.add_argument("--kissat", type=Path, default=DEFAULT_KISSAT, help="Kissat executable path")
    parser.add_argument("--timeout", type=float, default=None, help="Per-call timeout in seconds")
    parser.add_argument("--max-solutions", type=int, default=None, help="Stop after this many distinct keys")
    parser.add_argument("--solver", choices=("kissat", "cryptominisat"), default="kissat")
    parser.add_argument("--solver-path", type=Path)
    parser.add_argument("--xor", action="store_true", help="input is CryptoMiniSat XOR-CNF")
    parser.add_argument("--threads", type=int, default=1)
    args = parser.parse_args(argv)
    exit_code = 0
    for cnf in args.cnf:
        print(f"Banning Solution: {cnf}")
        try:
            result = banning_solution(cnf, kissat=args.kissat, timeout=args.timeout,
                                      max_solutions=args.max_solutions,
                                      solver=args.solver, solver_path=args.solver_path,
                                      xor_format=args.xor, threads=args.threads)
            print(f"status={result.status} keys={result.solution_count} calls={result.solver_calls} "
                  f"elapsed={result.elapsed_seconds:.3f}s")
            if result.error:
                print(result.error)
                exit_code = 1
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"ERROR: {exc}")
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
