
from pathlib import Path
import subprocess
import tempfile

KISSAT = Path("solvers/kissat/build/kissat")
INPUT_CNF = Path("data/test/kissat_test.cnf")


def read_cnf(path):
    """Read DIMACS CNF and return header and clauses."""
    lines = path.read_text().splitlines()

    header = None
    clauses = []

    for line in lines:
        line = line.strip()

        if not line or line.startswith("c"):
            continue

        if line.startswith("p"):
            header = line
        else:
            clauses.append(line)

    if header is None:
        raise ValueError("Missing DIMACS header")

    parts = header.split()
    if len(parts) != 4 or parts[1] != "cnf":
        raise ValueError("Invalid DIMACS header")

    num_vars = int(parts[2])

    return num_vars, clauses


def write_cnf(path, num_vars, clauses):
    """Write CNF with an updated clause count."""
    with path.open("w") as f:
        f.write(f"p cnf {num_vars} {len(clauses)}\n")

        for clause in clauses:
            f.write(clause + "\n")


def solve(kissat, cnf_path):
    """Run Kissat and return its status and complete model."""
    result = subprocess.run(
        [str(kissat), str(cnf_path), "--relaxed", "-q"],
        capture_output=True,
        text=True
    )

    output = result.stdout

    if "s UNSATISFIABLE" in output:
        return "UNSAT", None

    if "s SATISFIABLE" not in output:
        raise RuntimeError(
            f"Unexpected Kissat output:\n{output}\n"
            f"stderr:\n{result.stderr}"
        )

    model = []

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("v "):
            for item in line.split()[1:]:
                literal = int(item)

                if literal == 0:
                    return "SAT", model

                model.append(literal)

    raise RuntimeError("SAT result without a complete model")


def main():
    if not KISSAT.is_file():
        raise FileNotFoundError(f"Kissat not found: {KISSAT}")

    if not INPUT_CNF.is_file():
        raise FileNotFoundError(f"CNF not found: {INPUT_CNF}")

    num_vars, original_clauses = read_cnf(INPUT_CNF)

    solutions = []

    with tempfile.TemporaryDirectory() as temp_dir:
        working_cnf = Path(temp_dir) / "working.cnf"

        clauses = original_clauses.copy()

        while True:
            write_cnf(working_cnf, num_vars, clauses)

            status, model = solve(KISSAT.resolve(), working_cnf.resolve())

            if status == "UNSAT":
                print("UNSAT: no more models.")
                break

            solutions.append(model)

            print(
                f"Solution {len(solutions)}: "
                f"{model}"
            )

            # Blocking clause: negate every literal in the model.
            blocking_clause = " ".join(
                str(-literal) for literal in model
            ) + " 0"

            clauses.append(blocking_clause)

    print(f"\nTotal models found: {len(solutions)}")

    if len(solutions) != 2:
        raise AssertionError(
            f"Expected 2 models, found {len(solutions)}"
        )

    print("TEST PASSED")


if __name__ == "__main__":
    main()
