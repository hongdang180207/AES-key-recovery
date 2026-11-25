"""Run selected recovery methods over a shared dataset directory and compare keys."""

from __future__ import annotations

import argparse
import csv
import json
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

try:
    from .banning_solution import banning_solution
    from .brute_force import brute_force, thesis_brute_force
    from .mixed_approach import mixed_approach
    from .random_instancing import random_instancing
    from .common import DEFAULT_KISSAT, DEFAULT_CMS
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from src.approaches.banning_solution import banning_solution
    from src.approaches.brute_force import brute_force, thesis_brute_force
    from src.approaches.mixed_approach import mixed_approach
    from src.approaches.random_instancing import random_instancing
    from src.approaches.common import DEFAULT_KISSAT, DEFAULT_CMS


ROOT = Path(__file__).resolve().parents[2]


def _plain_result(result) -> dict:
    return asdict(result) if is_dataclass(result) else dict(result)


def load_manifest(path: str | Path | None) -> dict[str, str]:
    if path is None or not Path(path).is_file():
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {Path(item["name"]).stem: item["ground_truth_key_hex"].lower()
            for item in data.get("datasets", []) if item.get("ground_truth_key_hex")}


def run_experiments(input_dir: str | Path, *, methods: Sequence[str] = ("banning", "brute_force", "mixed", "random_instancing"),
                    pattern: str = "*.cnf", xor_format: bool = False,
                    solver: str | None = None, solver_path: str | Path | None = None,
                    timeout: float | None = None, overall_timeout: float | None = None,
                    brute_mode: str = "thesis-sat", infer_bits: int = 8,
                    random_bits: int = 8, random_seed: int = 1,
                    max_assignments: int | None = None,
                    max_solutions: int | None = None,
                    manifest: str | Path | None = None) -> dict:
    input_dir = Path(input_dir).resolve()
    if not input_dir.is_dir():
        raise FileNotFoundError(input_dir)
    files = sorted(input_dir.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No inputs matched {input_dir / pattern}")
    valid_methods = {"banning", "brute_force", "mixed", "random_instancing"}
    unknown = set(methods) - valid_methods
    if unknown:
        raise ValueError(f"Unknown method(s): {', '.join(sorted(unknown))}")
    actual_solver = solver or ("cryptominisat" if xor_format else "kissat")
    if solver_path is None:
        solver_path = DEFAULT_CMS if actual_solver == "cryptominisat" else DEFAULT_KISSAT
    truth = load_manifest(manifest)
    rows = []
    started_all = time.perf_counter()

    for file_index, cnf in enumerate(files):
        print(f"\n=== Dataset {file_index + 1}/{len(files)}: {cnf.name} ===", flush=True)
        for method in methods:
            print(f"--- {method} ---", flush=True)
            started = time.perf_counter()
            try:
                if method == "banning":
                    result = banning_solution(cnf, timeout=timeout,
                                              max_solutions=max_solutions,
                                              solver=actual_solver, solver_path=solver_path,
                                              xor_format=xor_format)
                elif method == "brute_force":
                    if brute_mode == "schedule":
                        result = brute_force(cnf, max_candidates=max_assignments,
                                             timeout=overall_timeout,
                                             xor_format=xor_format)
                    else:
                        result = thesis_brute_force(cnf, infer_bits=infer_bits,
                                                    max_assignments=max_assignments,
                                                    timeout=timeout, xor_format=xor_format,
                                                    solver=actual_solver, solver_path=solver_path)
                elif method == "mixed":
                    result = mixed_approach(cnf, infer_bits=infer_bits,
                                            max_guesses=max_assignments,
                                            max_solutions=max_solutions,
                                            timeout=timeout, overall_timeout=overall_timeout,
                                            solver=actual_solver, solver_path=solver_path,
                                            xor_format=xor_format)
                else:
                    result = random_instancing(cnf, sample_bits=random_bits,
                                               max_assignments=max_assignments,
                                               target_solutions=max_solutions,
                                               seed=random_seed + file_index,
                                               timeout=timeout, overall_timeout=overall_timeout,
                                               solver=actual_solver, solver_path=solver_path,
                                               xor_format=xor_format)
                details = _plain_result(result)
                status = details.get("status", "UNKNOWN")
            except KeyboardInterrupt:
                status, details = "INTERRUPTED", {"error": "interrupted by user"}
                raise
            except Exception as exc:
                status, details = "ERROR", {"error": f"{type(exc).__name__}: {exc}"}
                print(f"{status}: {details['error']}", flush=True)
            elapsed = time.perf_counter() - started
            keys = [key.lower() for key in details.get("keys_hex", [])]
            ground_truth = truth.get(cnf.stem)
            rows.append({
                "dataset": cnf.name, "method": method, "status": status,
                "solution_count": details.get("solution_count", len(keys)),
                "elapsed_seconds": round(details.get("elapsed_seconds", elapsed), 6),
                "solver_calls": details.get("solver_calls"),
                "keys_hex": keys,
                "ground_truth_key_hex": ground_truth,
                "ground_truth_found": (ground_truth in keys) if ground_truth else None,
                "detail": details,
            })

    elapsed_all = time.perf_counter() - started_all
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = ROOT / "results" / "timings"
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"comparison_{stamp}.json"
    csv_path = output_dir / f"comparison_{stamp}.csv"
    summary = {"input_dir": str(input_dir), "methods": list(methods),
               "format": "xor" if xor_format else "standard", "solver": actual_solver,
               "elapsed_seconds": elapsed_all, "rows": rows}
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    fields = ["dataset", "method", "status", "solution_count", "elapsed_seconds",
              "solver_calls", "ground_truth_found", "keys_hex"]
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, "keys_hex": ";".join(row["keys_hex"])})
    print(f"\nComparison saved: {csv_path}", flush=True)
    print(f"Detailed results: {json_path}", flush=True)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=ROOT / "data" / "cnf" / "standard")
    parser.add_argument("--pattern", default="*.cnf")
    parser.add_argument("--methods", default="banning,brute_force,mixed,random_instancing")
    parser.add_argument("--xor", action="store_true")
    parser.add_argument("--solver", choices=("kissat", "cryptominisat"))
    parser.add_argument("--solver-path", type=Path)
    parser.add_argument("--timeout", type=float, help="seconds per solver call")
    parser.add_argument("--overall-timeout", type=float)
    parser.add_argument("--brute-mode", choices=("schedule", "thesis-sat"), default="thesis-sat")
    parser.add_argument("--infer-bits", type=int, default=8)
    parser.add_argument("--random-bits", type=int, default=8)
    parser.add_argument("--random-seed", type=int, default=1)
    parser.add_argument("--max-assignments", type=int)
    parser.add_argument("--max-solutions", type=int)
    parser.add_argument("--manifest", type=Path, default=ROOT / "data" / "test" / "manifest.json")
    args = parser.parse_args(argv)
    run_experiments(args.input_dir,
                    methods=[part.strip() for part in args.methods.split(",") if part.strip()],
                    pattern=args.pattern, xor_format=args.xor, solver=args.solver,
                    solver_path=args.solver_path, timeout=args.timeout,
                    overall_timeout=args.overall_timeout, brute_mode=args.brute_mode,
                    infer_bits=args.infer_bits, random_bits=args.random_bits,
                    random_seed=args.random_seed, max_assignments=args.max_assignments,
                    max_solutions=args.max_solutions, manifest=args.manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
