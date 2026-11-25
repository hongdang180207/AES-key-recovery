"""Random instancing following the thesis appendix.

Choose a random subset of currently unobserved round-key bits, enumerate every
assignment to that subset, add each assignment to the CNF and use the banning
SAT loop to enumerate distinct master keys for that instance.
"""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path
from typing import Sequence

try:
    from .banning_solution import binary_to_hex, key_blocking_clause, model_to_binary
    from .common import (read_problem, result_paths, solve_with_solver, write_problem,
                         write_key_record, write_summary, read_schedule_unit_observations,
                         key_variables_from_round, validate_aes128_key)
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from src.approaches.banning_solution import binary_to_hex, key_blocking_clause, model_to_binary
    from src.approaches.common import (read_problem, result_paths, solve_with_solver, write_problem,
                                       write_key_record, write_summary, read_schedule_unit_observations,
                                       key_variables_from_round, validate_aes128_key)


def random_instancing(input_cnf: str | Path, *, sample_bits: int = 8,
                      random_subsets: int = 1, max_assignments: int | None = None,
                      target_solutions: int | None = None, seed: int = 1,
                      timeout: float | None = None, overall_timeout: float | None = None,
                      solver: str = "kissat", solver_path: str | Path | None = None,
                      xor_format: bool = False, threads: int = 1,
                      bit_pool: Sequence[int] | None = None) -> dict:
    input_cnf = Path(input_cnf).resolve()
    if not input_cnf.is_file():
        raise FileNotFoundError(input_cnf)
    if sample_bits < 0 or random_subsets < 1:
        raise ValueError("sample_bits must be non-negative and random_subsets positive")
    if max_assignments is not None and max_assignments < 1:
        raise ValueError("max_assignments must be positive")
    if target_solutions is not None and target_solutions < 1:
        raise ValueError("target_solutions must be positive")

    num_vars, original, xor_equations = read_problem(input_cnf, xor_format=xor_format)
    observations = read_schedule_unit_observations(input_cnf, xor_format=xor_format)
    schedule_vars = {var for round_index in range(1, 11)
                     for var in key_variables_from_round(round_index, range(128))}
    fixed_vars = {key_variables_from_round(round_index, [bit])[0]
                  for round_index, bits in observations.items() for bit in bits}
    pool = list(bit_pool) if bit_pool is not None else sorted(schedule_vars - fixed_vars)
    if len(set(pool)) != len(pool) or any(var not in schedule_vars or var in fixed_vars
                                          or var > num_vars for var in pool):
        raise ValueError("bit_pool must contain distinct, unobserved round-key output variables")
    if sample_bits > len(pool):
        raise ValueError("sample_bits exceeds the eligible unobserved-bit pool")

    solutions_path, timing_path = result_paths(input_cnf.name, "random_instancing")
    root = Path(__file__).resolve().parents[2]
    trace_path = root / "results" / "logs" / f"random_instancing_{input_cnf.stem}_instances.jsonl"
    work_path = root / "results" / "logs" / f"random_instancing_{input_cnf.stem}_working.cnf"
    for path in (solutions_path, trace_path):
        path.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)
    global_key_blocks: list[list[int]] = []
    keys: list[str] = []
    solver_calls = 0
    assignments_done = 0
    subsets: list[list[int]] = []
    call_times: list[float] = []
    status = "COMPLETE"
    started = time.perf_counter()
    try:
        with solutions_path.open("w", encoding="utf-8", newline="\n") as output, \
             trace_path.open("w", encoding="utf-8", newline="\n") as trace:
            stop = False
            for subset_index in range(random_subsets):
                selected = sorted(rng.sample(pool, sample_bits))
                subsets.append(selected)
                assignment_count = 1 << sample_bits
                print(f"Random subset {subset_index + 1}/{random_subsets}: "
                      f"{sample_bits} bits, {assignment_count} assignments", flush=True)
                for assignment_index in range(assignment_count):
                    if max_assignments is not None and assignments_done >= max_assignments:
                        status = "ASSIGNMENT_LIMIT"
                        stop = True
                        break
                    if target_solutions is not None and len(keys) >= target_solutions:
                        status = "TARGET_REACHED"
                        stop = True
                        break
                    if overall_timeout is not None and time.perf_counter() - started >= overall_timeout:
                        status = "TIMEOUT"
                        stop = True
                        break
                    values = [(assignment_index >> (sample_bits - 1 - j)) & 1
                              for j in range(sample_bits)]
                    assumptions = [[var if value else -var] for var, value in zip(selected, values)]
                    clauses = list(original) + list(global_key_blocks) + assumptions
                    assignments_done += 1
                    print(f"  instance {assignments_done}: assignment "
                          f"{''.join(map(str, values)) or '(empty)'}", flush=True)
                    while True:
                        if overall_timeout is not None and time.perf_counter() - started >= overall_timeout:
                            status = "TIMEOUT"
                            stop = True
                            break
                        write_problem(work_path, num_vars, clauses, xor_equations,
                                      xor_format=xor_format)
                        solved = solve_with_solver(work_path, solver=solver, solver_path=solver_path,
                                                   timeout=timeout, xor_format=xor_format, threads=threads)
                        solver_calls += 1
                        call_times.append(solved.elapsed_seconds)
                        record = {"subset_index": subset_index, "variables": selected,
                                  "assignment_index": assignment_index, "values": values,
                                  "status": solved.status,
                                  "solver_call_seconds": solved.elapsed_seconds}
                        if solved.status == "UNSAT":
                            trace.write(json.dumps(record) + "\n")
                            trace.flush()
                            break
                        if solved.status != "SAT":
                            status = solved.status
                            trace.write(json.dumps(record) + "\n")
                            trace.flush()
                            stop = True
                            break
                        assert solved.model is not None
                        key_hex = binary_to_hex(model_to_binary(solved.model))
                        if not validate_aes128_key(key_hex, observations):
                            raise RuntimeError(f"SAT key violates observed AES schedule bits: {key_hex}")
                        block = key_blocking_clause(solved.model)
                        global_key_blocks.append(block)
                        clauses.append(block)
                        record["key_hex"] = key_hex
                        if key_hex not in keys:
                            keys.append(key_hex)
                            write_key_record(output, len(keys), key_hex,
                                             time.perf_counter() - started, solved.elapsed_seconds,
                                             subset_index=subset_index,
                                             assignment_index=assignment_index,
                                             instantiated_variables=selected,
                                             instantiated_values=values)
                            print(f"    key {len(keys)}: {key_hex}", flush=True)
                        trace.write(json.dumps(record) + "\n")
                        trace.flush()
                        if target_solutions is not None and len(keys) >= target_solutions:
                            status = "TARGET_REACHED"
                            stop = True
                            break
                    if stop:
                        break
                if stop:
                    break
            else:
                status = "COMPLETE"
    except KeyboardInterrupt:
        status = "INTERRUPTED"
    finally:
        work_path.unlink(missing_ok=True)

    elapsed = time.perf_counter() - started
    summary = {"approach": "random_instancing", "input_file": str(input_cnf),
               "status": status, "seed": seed, "sample_bits": sample_bits,
               "random_subsets": random_subsets, "selected_subsets": subsets,
               "assignments_requested_per_subset": 1 << sample_bits,
               "assignments_done": assignments_done, "solver_calls": solver_calls,
               "solution_count": len(keys), "keys_hex": keys,
               "solver_call_seconds": call_times, "elapsed_seconds": elapsed,
               "timeout_per_call_seconds": timeout, "overall_timeout_seconds": overall_timeout,
               "max_assignments": max_assignments, "target_solutions": target_solutions}
    write_summary(timing_path, summary)
    print(f"Random instancing {status}: assignments={assignments_done}, "
          f"calls={solver_calls}, keys={len(keys)}, elapsed={elapsed:.1f}s", flush=True)
    return summary


def _parse_variables(value: str) -> list[int]:
    try:
        return [int(part) for part in value.split(",") if part.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("variables must be comma-separated integers") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cnf", type=Path)
    parser.add_argument("--sample-bits", type=int, default=8)
    parser.add_argument("--random-subsets", type=int, default=1)
    parser.add_argument("--max-assignments", type=int)
    parser.add_argument("--target-solutions", type=int)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=None, help="per solver call seconds")
    parser.add_argument("--overall-timeout", type=float, default=None)
    parser.add_argument("--solver", choices=("kissat", "cryptominisat"), default="kissat")
    parser.add_argument("--solver-path", type=Path)
    parser.add_argument("--xor", action="store_true", help="input is CryptoMiniSat XOR-CNF")
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--bit-pool", type=_parse_variables,
                        help="comma-separated schedule variable IDs; default is all unobserved bits")
    args = parser.parse_args(argv)
    random_instancing(args.cnf, sample_bits=args.sample_bits,
                      random_subsets=args.random_subsets, max_assignments=args.max_assignments,
                      target_solutions=args.target_solutions, seed=args.seed,
                      timeout=args.timeout, overall_timeout=args.overall_timeout,
                      solver=args.solver, solver_path=args.solver_path,
                      xor_format=args.xor, threads=args.threads, bit_pool=args.bit_pool)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
