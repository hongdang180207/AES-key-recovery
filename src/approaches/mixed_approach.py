"""Mixed key recovery: enumerate selected key bits, solve the rest with SAT."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Sequence

try:
    from .banning_solution import binary_to_hex, key_blocking_clause, model_to_binary
    from .common import (result_paths, read_problem,
                         solve_with_solver, write_problem, write_key_record, write_summary,
                         read_schedule_unit_observations, key_variables_from_round,
                         validate_aes128_key, thesis_instanced_variables)
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from src.approaches.banning_solution import binary_to_hex, key_blocking_clause, model_to_binary
    from src.approaches.common import (result_paths, read_problem,
                                       solve_with_solver, write_problem, write_key_record, write_summary,
                                       read_schedule_unit_observations, key_variables_from_round,
                                       validate_aes128_key, thesis_instanced_variables)


def mixed_approach(input_cnf: str | Path, *, infer_bits: int = 8,
                   guess_variables: Sequence[int] | None = None,
                   max_guesses: int | None = None, max_solutions: int | None = None,
                   timeout: float | None = None, overall_timeout: float | None = None,
                   solver: str = "kissat", solver_path: str | Path | None = None,
                   xor_format: bool = False, threads: int = 1) -> dict:
    input_cnf = Path(input_cnf).resolve()
    if not input_cnf.is_file():
        raise FileNotFoundError(input_cnf)
    num_vars, original, xor_equations = read_problem(input_cnf, xor_format=xor_format)
    observations = read_schedule_unit_observations(input_cnf, xor_format=xor_format)
    if guess_variables is None:
        # The appendix splits guessed bits across the partial round-1 and
        # round-10 keys before running the banning loop for each combination.
        guess_variables = thesis_instanced_variables(observations, infer_bits)
    else:
        infer_bits = len(guess_variables)
        guess_variables = list(guess_variables)
        if len(guess_variables) > 128 or len(set(guess_variables)) != len(guess_variables):
            raise ValueError("guess_variables must contain at most 128 distinct IDs")
        schedule_vars = {var for round_index in range(1, 11)
                         for var in key_variables_from_round(round_index, range(128))}
        known_vars = {key_variables_from_round(r, [b])[0]
                      for r, bits in observations.items() for b in bits}
        if any(var not in schedule_vars or var in known_vars or var > num_vars for var in guess_variables):
            raise ValueError("Mixed guess variables must be unobserved AES round-key output bits")
    total_guesses = 1 << len(guess_variables)
    if max_guesses is not None and max_guesses < 1:
        raise ValueError("max_guesses must be positive")
    if max_solutions is not None and max_solutions < 1:
        raise ValueError("max_solutions must be positive")

    solutions_path, timing_path = result_paths(input_cnf.name, "mixed")
    trace_path = Path(__file__).resolve().parents[2] / "results" / "logs" / f"mixed_{input_cnf.stem}_calls.jsonl"
    for path in (solutions_path, trace_path):
        path.parent.mkdir(parents=True, exist_ok=True)
    work_path = trace_path.parent / f"mixed_{input_cnf.stem}_working.cnf"
    keys: list[str] = []
    solver_calls = 0
    guesses_done = 0
    elapsed_calls: list[float] = []
    status = "COMPLETE"
    started = time.perf_counter()
    try:
        with solutions_path.open("w", encoding="utf-8", newline="\n") as output, \
             trace_path.open("w", encoding="utf-8", newline="\n") as trace:
            for guess_index in range(total_guesses):
                if max_guesses is not None and guesses_done >= max_guesses:
                    status = "GUESS_LIMIT"
                    break
                if max_solutions is not None and len(keys) >= max_solutions:
                    status = "SOLUTION_LIMIT"
                    break
                if overall_timeout is not None and time.perf_counter() - started >= overall_timeout:
                    status = "TIMEOUT"
                    break
                guess_bits_value = [(guess_index >> (len(guess_variables) - 1 - i)) & 1
                                    for i in range(len(guess_variables))]
                units = [[var if bit else -var]
                         for var, bit in zip(guess_variables, guess_bits_value)]
                branch_clauses = list(original) + units
                guesses_done += 1
                print(f"Mixed guess {guesses_done}/{min(total_guesses, max_guesses or total_guesses)}: "
                      f"{''.join(map(str, guess_bits_value)) or '(none)'}", flush=True)
                while True:
                    if overall_timeout is not None and time.perf_counter() - started >= overall_timeout:
                        status = "TIMEOUT"
                        break
                    write_problem(work_path, num_vars, branch_clauses,
                                  xor_equations, xor_format=xor_format)
                    print(f"  SAT call {solver_calls + 1}", flush=True)
                    solved = solve_with_solver(work_path, solver=solver, solver_path=solver_path,
                                               timeout=timeout, xor_format=xor_format, threads=threads)
                    solver_calls += 1
                    elapsed_calls.append(solved.elapsed_seconds)
                    trace.write(json.dumps({"guess_index": guess_index,
                                            "guess_bits": guess_bits_value,
                                            "status": solved.status,
                                            "elapsed_seconds": solved.elapsed_seconds}) + "\n")
                    trace.flush()
                    print(f"  {solved.status} after {solved.elapsed_seconds:.2f}s", flush=True)
                    if solved.status == "UNSAT":
                        break
                    if solved.status != "SAT":
                        status = solved.status
                        break
                    assert solved.model is not None
                    key_hex = binary_to_hex(model_to_binary(solved.model))
                    if not validate_aes128_key(key_hex, observations):
                        raise RuntimeError(f"Recovered key fails AES key-schedule observations: {key_hex}")
                    if key_hex not in keys:
                        keys.append(key_hex)
                        write_key_record(output, len(keys), key_hex,
                                         time.perf_counter() - started, solved.elapsed_seconds,
                                         guess_index=guess_index, guessed_bits=guess_bits_value)
                        print(f"  key {len(keys)}: {key_hex}", flush=True)
                    branch_clauses.append(key_blocking_clause(solved.model))
                    if max_solutions is not None and len(keys) >= max_solutions:
                        status = "SOLUTION_LIMIT"
                        break
                if status in {"TIMEOUT", "UNKNOWN", "ERROR", "INTERRUPTED"}:
                    break
    except KeyboardInterrupt:
        status = "INTERRUPTED"
    finally:
        work_path.unlink(missing_ok=True)

    elapsed = time.perf_counter() - started
    summary = {"approach": "mixed", "input_file": str(input_cnf), "status": status,
               "inferred_bits": infer_bits, "guess_variables": list(guess_variables), "total_guesses": total_guesses,
               "guesses_done": guesses_done, "solver_calls": solver_calls,
               "solution_count": len(keys), "keys_hex": keys,
               "solver_call_seconds": elapsed_calls, "elapsed_seconds": elapsed,
               "timeout_per_call_seconds": timeout, "overall_timeout_seconds": overall_timeout,
               "max_guesses": max_guesses, "max_solutions": max_solutions}
    write_summary(timing_path, summary)
    print(f"Mixed {status}: guesses={guesses_done}, calls={solver_calls}, "
          f"keys={len(keys)}, elapsed={elapsed:.1f}s", flush=True)
    return summary


def _parse_variables(value: str) -> list[int]:
    try:
        return [int(part) for part in value.split(",") if part.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("variables must be comma-separated positive integers") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cnf", type=Path)
    parser.add_argument("--infer-bits", "--guess-bits", dest="infer_bits", type=int, default=8,
                        help="total fixed bits, split equally between round 1 and round 10")
    parser.add_argument("--guess-variables", type=_parse_variables)
    parser.add_argument("--max-guesses", type=int)
    parser.add_argument("--max-solutions", type=int)
    parser.add_argument("--timeout", type=float, default=None, help="per solver call seconds")
    parser.add_argument("--overall-timeout", type=float, default=None)
    parser.add_argument("--solver", choices=("kissat", "cryptominisat"), default="kissat")
    parser.add_argument("--solver-path", type=Path)
    parser.add_argument("--xor", action="store_true", help="input is CryptoMiniSat XOR-CNF")
    parser.add_argument("--threads", type=int, default=1)
    args = parser.parse_args(argv)
    mixed_approach(args.cnf, infer_bits=args.infer_bits, guess_variables=args.guess_variables,
                   max_guesses=args.max_guesses, max_solutions=args.max_solutions,
                   timeout=args.timeout, overall_timeout=args.overall_timeout,
                   solver=args.solver, solver_path=args.solver_path,
                   xor_format=args.xor, threads=args.threads)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
