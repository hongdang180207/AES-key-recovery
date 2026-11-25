"""Brute-force missing bits of an observed AES-128 round key.

The CNF generator numbers schedule bits exactly as in the thesis. Unit clauses
are read as observed schedule bits; a candidate complete round key is reversed
to the master key, expanded, and checked against every observed bit.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Sequence

try:
    from .banning_solution import model_to_binary
    from ..cnf.aeskeyschedule2 import key_schedule, reverse_key_schedule
    from .common import (key_variables_from_round, read_problem, result_paths, write_summary,
                         read_schedule_unit_observations, thesis_instanced_variables,
                         solve_with_solver, write_problem, write_key_record,
                         validate_aes128_key)
except ImportError:  # direct execution from the repository root
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from src.approaches.banning_solution import model_to_binary
    from src.cnf.aeskeyschedule2 import key_schedule, reverse_key_schedule
    from src.approaches.common import (key_variables_from_round, read_problem, result_paths,
                                       write_summary, read_schedule_unit_observations,
                                       thesis_instanced_variables, solve_with_solver,
                                       write_problem, write_key_record, validate_aes128_key)


def read_schedule_observations(cnf_path: str | Path, *, xor_format: bool = False) -> dict[int, dict[int, int]]:
    """Return {round: {bit_offset: bit_value}} from schedule-bit unit clauses."""
    _, clauses, _ = read_problem(cnf_path, xor_format=xor_format)
    variable_lookup = {
        variable: (round_index, bit_index)
        for round_index in range(11)
        for bit_index, variable in enumerate(key_variables_from_round(round_index, range(128)))
    }
    observations: dict[int, dict[int, int]] = {}
    for clause in clauses:
        if len(clause) != 1:
            continue
        literal = clause[0]
        coordinate = variable_lookup.get(abs(literal))
        if coordinate is None:
            continue
        round_index, bit_index = coordinate
        bit_value = int(literal > 0)
        previous = observations.setdefault(round_index, {}).get(bit_index)
        if previous is not None and previous != bit_value:
            raise ValueError(f"CNF has contradictory units for round {round_index} bit {bit_index}")
        observations[round_index][bit_index] = bit_value
    if not observations:
        raise ValueError("No known AES round-key bits found as unit clauses in this CNF")
    return observations


def _key_matches_observations(round_keys: Sequence[bytes],
                              observations: dict[int, dict[int, int]]) -> bool:
    for round_index, known_bits in observations.items():
        value = int.from_bytes(round_keys[round_index], "big")
        for bit_index, expected in known_bits.items():
            if ((value >> (127 - bit_index)) & 1) != expected:
                return False
    return True


def brute_force(input_cnf: str | Path, *, max_candidates: int | None = None,
                timeout: float | None = None, progress_every: int = 100_000,
                xor_format: bool = False,
                solution_path: str | Path | None = None,
                timing_path: str | Path | None = None) -> dict:
    input_cnf = Path(input_cnf).resolve()
    if not input_cnf.is_file():
        raise FileNotFoundError(input_cnf)
    if max_candidates is not None and max_candidates < 1:
        raise ValueError("max_candidates must be positive")
    observations = read_schedule_observations(input_cnf, xor_format=xor_format)
    chosen_round = max(observations, key=lambda r: (len(observations[r]), r))
    known = observations[chosen_round]
    unknown_bits = [bit for bit in range(128) if bit not in known]
    base_value = sum(value << (127 - bit) for bit, value in known.items())
    total_space = 1 << len(unknown_bits)
    expected_candidates = min(total_space, max_candidates) if max_candidates else total_space

    default_solution, default_timing = result_paths(input_cnf.name, "brute_force")
    solution_path = Path(solution_path or default_solution)
    timing_path = Path(timing_path or default_timing)
    solution_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    checked = 0
    keys: list[str] = []
    status = "COMPLETE"
    try:
        with solution_path.open("w", encoding="utf-8", newline="\n") as output:
            for candidate_index in range(total_space):
                if max_candidates is not None and checked >= max_candidates:
                    status = "CANDIDATE_LIMIT"
                    break
                if timeout is not None and time.perf_counter() - started >= timeout:
                    status = "TIMEOUT"
                    break
                candidate = base_value
                for j, bit_index in enumerate(unknown_bits):
                    if (candidate_index >> (len(unknown_bits) - 1 - j)) & 1:
                        candidate |= 1 << (127 - bit_index)
                round_key = candidate.to_bytes(16, "big")
                master_key = reverse_key_schedule(round_key, chosen_round)
                expanded = key_schedule(master_key)
                checked += 1
                if _key_matches_observations(expanded, observations):
                    key_hex = master_key.hex()
                    keys.append(key_hex)
                    output.write(json.dumps({"index": len(keys), "key_hex": key_hex,
                                             "candidate_index": candidate_index,
                                             "source_round": chosen_round,
                                             "elapsed_seconds": time.perf_counter() - started}) + "\n")
                    output.flush()
                    print(f"Found key {len(keys)}: {key_hex}", flush=True)
                if progress_every > 0 and checked % progress_every == 0:
                    elapsed = time.perf_counter() - started
                    print(f"Checked {checked:,}/{expected_candidates:,} candidates "
                          f"({elapsed:.1f}s); keys={len(keys)}", flush=True)
    except KeyboardInterrupt:
        status = "INTERRUPTED"
    elapsed = time.perf_counter() - started
    summary = {
        "approach": "brute_force", "input_file": str(input_cnf), "status": status,
        "source_round": chosen_round, "known_bits": len(known),
        "unknown_bits": len(unknown_bits), "search_space": total_space,
        "candidates_checked": checked, "solution_count": len(keys),
        "keys_hex": keys, "elapsed_seconds": elapsed,
        "timeout_seconds": timeout, "max_candidates": max_candidates,
    }
    write_summary(timing_path, summary)
    print(f"Brute force {status}: checked {checked:,}/{total_space:,}, "
          f"keys={len(keys)}, elapsed={elapsed:.1f}s", flush=True)
    return summary


def thesis_brute_force(input_cnf: str | Path, *, infer_bits: int = 8,
                       max_assignments: int | None = None,
                       timeout: float | None = None, xor_format: bool = False,
                       solver: str = "kissat", solver_path: str | Path | None = None,
                       threads: int = 1) -> dict:
    """Reproduce the appendix brute force: SAT once for every bit assignment."""
    input_cnf = Path(input_cnf).resolve()
    num_vars, original, xor_equations = read_problem(input_cnf, xor_format=xor_format)
    observations = read_schedule_unit_observations(input_cnf, xor_format=xor_format)
    guessed_variables = thesis_instanced_variables(observations, infer_bits)
    total_assignments = 1 << infer_bits
    if max_assignments is not None and max_assignments < 1:
        raise ValueError("max_assignments must be positive")

    solution_path, timing_path = result_paths(input_cnf.name, "brute_force_thesis")
    log_dir = Path(__file__).resolve().parents[2] / "results" / "logs"
    trace_path = log_dir / f"brute_force_{input_cnf.stem}_instances.jsonl"
    work_path = log_dir / f"brute_force_{input_cnf.stem}_working.cnf"
    solution_path.parent.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    work_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    assignments_done = solver_calls = unsat_count = 0
    call_times: list[float] = []
    keys: list[str] = []
    status = "COMPLETE"
    try:
        with solution_path.open("w", encoding="utf-8", newline="\n") as output, \
             trace_path.open("w", encoding="utf-8", newline="\n") as trace:
            for assignment_index in range(total_assignments):
                if max_assignments is not None and assignments_done >= max_assignments:
                    status = "ASSIGNMENT_LIMIT"
                    break
                values = [(assignment_index >> (infer_bits - 1 - i)) & 1
                          for i in range(infer_bits)]
                assumptions = [[var if value else -var]
                               for var, value in zip(guessed_variables, values)]
                write_problem(work_path, num_vars, list(original) + assumptions,
                              xor_equations, xor_format=xor_format)
                assignments_done += 1
                print(f"Brute-force instance {assignments_done}/{total_assignments}: "
                      f"{''.join(map(str, values)) or '(empty)'}", flush=True)
                solved = solve_with_solver(work_path, solver=solver, solver_path=solver_path,
                                           timeout=timeout, xor_format=xor_format, threads=threads)
                solver_calls += 1
                call_times.append(solved.elapsed_seconds)
                instance_record = {"assignment_index": assignment_index,
                                   "instantiated_variables": guessed_variables,
                                   "instantiated_values": values,
                                   "status": solved.status,
                                   "solver_call_seconds": solved.elapsed_seconds}
                if solved.status == "UNSAT":
                    unsat_count += 1
                    trace.write(json.dumps(instance_record) + "\n")
                    trace.flush()
                    continue
                if solved.status != "SAT":
                    status = solved.status
                    trace.write(json.dumps(instance_record) + "\n")
                    trace.flush()
                    break
                assert solved.model is not None
                key_hex = f"{int(model_to_binary(solved.model), 2):032x}"
                if not validate_aes128_key(key_hex, observations):
                    raise RuntimeError(f"SAT candidate fails the AES key schedule: {key_hex}")
                if key_hex not in keys:
                    keys.append(key_hex)
                    write_key_record(output, len(keys), key_hex,
                                     time.perf_counter() - started, solved.elapsed_seconds,
                                     assignment_index=assignment_index,
                                     instantiated_variables=guessed_variables,
                                     instantiated_values=values)
                    print(f"  key {len(keys)}: {key_hex}", flush=True)
                instance_record["key_hex"] = key_hex
                trace.write(json.dumps(instance_record) + "\n")
                trace.flush()
    except KeyboardInterrupt:
        status = "INTERRUPTED"
    finally:
        work_path.unlink(missing_ok=True)
    elapsed = time.perf_counter() - started
    summary = {"approach": "brute_force_thesis", "input_file": str(input_cnf),
               "status": status, "inferred_bits": infer_bits,
               "instantiated_variables": guessed_variables,
               "total_assignments": total_assignments, "assignments_done": assignments_done,
               "solver_calls": solver_calls, "unsat_assignments": unsat_count,
               "solution_count": len(keys), "keys_hex": keys,
               "solver_call_seconds": call_times, "trace_file": str(trace_path),
               "elapsed_seconds": elapsed,
               "max_assignments": max_assignments, "timeout_per_call_seconds": timeout}
    write_summary(timing_path, summary)
    print(f"Brute force (thesis) {status}: assignments={assignments_done}, "
          f"SAT={len(keys)}, UNSAT={unsat_count}, elapsed={elapsed:.1f}s", flush=True)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cnf", type=Path)
    parser.add_argument("--max-candidates", type=int, default=None,
                        help="optional cap for schedule candidates or thesis-SAT instances")
    parser.add_argument("--timeout", type=float, default=None, help="overall wall-clock limit in seconds")
    parser.add_argument("--progress-every", type=int, default=100_000)
    parser.add_argument("--xor", action="store_true", help="read CryptoMiniSat XOR-CNF")
    parser.add_argument("--strategy", choices=("schedule", "thesis-sat"), default="schedule",
                        help="schedule: pure key-schedule enumeration; thesis-sat: one SAT call per guessed-bit assignment")
    parser.add_argument("--infer-bits", type=int, default=8,
                        help="even guessed-bit count for thesis-sat, split between round 1 and round 10")
    parser.add_argument("--solver", choices=("kissat", "cryptominisat"), default="kissat")
    parser.add_argument("--solver-path", type=Path)
    parser.add_argument("--threads", type=int, default=1)
    args = parser.parse_args(argv)
    if args.strategy == "schedule":
        brute_force(args.cnf, max_candidates=args.max_candidates, timeout=args.timeout,
                    progress_every=args.progress_every, xor_format=args.xor)
    else:
        thesis_brute_force(args.cnf, infer_bits=args.infer_bits,
                           max_assignments=args.max_candidates, timeout=args.timeout,
                           xor_format=args.xor, solver=args.solver,
                           solver_path=args.solver_path, threads=args.threads)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
