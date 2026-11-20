
from pathlib import Path
import subprocess
import time
import shutil


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_DIR = PROJECT_ROOT / "data" / "cnf" / "standard"
WORK_DIR = PROJECT_ROOT / "results" / "logs"
SOLUTION_DIR = PROJECT_ROOT / "results" / "solutions"
TIMING_DIR = PROJECT_ROOT / "results" / "timings"

KISSAT = PROJECT_ROOT / "solvers" / "kissat" / "build" / "kissat"


# ============================================================
# DIMACS CNF FUNCTIONS
# ============================================================

def read_cnf(path):
    """Read and validate a DIMACS CNF file."""

    num_vars = None
    declared_clauses = None
    clauses = []
    current_clause = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("c"):
                continue

            if line.startswith("p"):
                if num_vars is not None:
                    raise ValueError("Multiple DIMACS headers found")

                parts = line.split()

                if len(parts) != 4 or parts[1] != "cnf":
                    raise ValueError("Invalid DIMACS header")

                num_vars = int(parts[2])
                declared_clauses = int(parts[3])
                continue

            if num_vars is None:
                raise ValueError("Clause found before DIMACS header")

            for token in line.split():
                literal = int(token)

                if literal == 0:
                    clauses.append(
                        " ".join(map(str, current_clause)) + " 0"
                    )
                    current_clause = []
                else:
                    if abs(literal) > num_vars:
                        raise ValueError(
                            f"Literal {literal} exceeds "
                            f"declared variable count"
                        )

                    current_clause.append(literal)

    if num_vars is None:
        raise ValueError("Missing DIMACS header")

    if current_clause:
        raise ValueError("Clause is missing terminating 0")

    if len(clauses) != declared_clauses:
        raise ValueError(
            f"Header declares {declared_clauses} clauses, "
            f"but found {len(clauses)}"
        )

    return num_vars, clauses


def write_cnf(path, num_vars, clauses):
    """Write a DIMACS CNF with an accurate clause count."""

    with path.open("w", encoding="utf-8") as file:
        file.write(f"p cnf {num_vars} {len(clauses)}\n")

        for clause in clauses:
            file.write(clause + "\n")


# ============================================================
# KISSAT
# ============================================================

def solve_with_kissat(cnf_path):
    """Run Kissat and return SAT status and model."""

    result = subprocess.run(
        [
            str(KISSAT),
            str(cnf_path),
            "--relaxed",
            "-q"
        ],
        capture_output=True,
        text=True
    )

    output = result.stdout

    if "s UNSATISFIABLE" in output:
        return "UNSAT", None

    if "s SATISFIABLE" not in output:
        raise RuntimeError(
            "Unexpected Kissat output:\n"
            + output
            + "\n"
            + result.stderr
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


# ============================================================
# SOLUTION CONVERSION
# ============================================================

def model_to_binary(model):
    """
    Extract the 128 initial AES key bits using variable IDs 1..128.

    Original thesis convention:
        negative literal -> bit 1
        positive literal -> bit 0
    """

    assignments = {
        abs(literal): literal
        for literal in model
    }

    missing = [
        var_id
        for var_id in range(1, 129)
        if var_id not in assignments
    ]

    if missing:
        raise ValueError(
            f"Model is missing key variables: {missing}"
        )

    return "".join(
        "1" if assignments[var_id] < 0 else "0"
        for var_id in range(1, 129)
    )


def binary_to_hex(binary):
    """Convert a 128-bit binary string into 32 hex digits."""

    return f"{int(binary, 2):032x}"


def hex_to_ascii(hex_string):
    """Convert hexadecimal data into readable ASCII."""

    return bytes.fromhex(hex_string).decode(
        "utf-8",
        errors="replace"
    )


# ============================================================
# BANNING SOLUTION
# ============================================================

def banning_solution(input_file):

    input_file = Path(input_file).resolve()

    if not input_file.is_file():
        raise FileNotFoundError(input_file)

    if not KISSAT.is_file():
        raise FileNotFoundError(
            f"Kissat executable not found: {KISSAT}"
        )

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    SOLUTION_DIR.mkdir(parents=True, exist_ok=True)
    TIMING_DIR.mkdir(parents=True, exist_ok=True)

    filename = input_file.stem

    working_file = WORK_DIR / f"{filename}_working.cnf"
    solution_file = SOLUTION_DIR / f"{filename}_solutions.txt"
    timing_file = TIMING_DIR / f"{filename}_timing.txt"

    num_vars, original_clauses = read_cnf(input_file)

    clauses = original_clauses.copy()

    solution_count = 0

    start_time = time.time()

    print(f"\nStarting Banning Solution: {filename}")

    with solution_file.open("w", encoding="utf-8") as output:

        while True:

            write_cnf(
                working_file,
                num_vars,
                clauses
            )

            status, model = solve_with_kissat(working_file)

            if status == "UNSAT":
                print("UNSAT: no more models.")
                break

            solution_count += 1

            elapsed = time.time() - start_time

            print(
                f"Solution {solution_count} found "
                f"({elapsed:.4f} seconds)"
            )

            binary = model_to_binary(model)

            hexadecimal = binary_to_hex(binary)

            ascii_string = hex_to_ascii(hexadecimal)

            output.write(
                f"SOLUTION {solution_count}\n"
            )

            output.write(
                f"Time: {elapsed:.6f} seconds\n"
            )

            output.write(
                f"Binary: {binary}\n"
            )

            output.write(
                f"Hex: {hexadecimal}\n"
            )

            output.write(
                f"ASCII: {ascii_string}\n\n"
            )

            # Blocking clause:
            # negate every literal in the complete SAT model.

            blocking_clause = " ".join(
                str(-literal)
                for literal in model
            ) + " 0"

            clauses.append(blocking_clause)

    total_time = time.time() - start_time

    working_file.unlink(missing_ok=True)

    with timing_file.open("w", encoding="utf-8") as timing:

        timing.write(
            f"Input file: {input_file.name}\n"
        )

        timing.write(
            f"Number of models: {solution_count}\n"
        )

        timing.write(
            f"Total time: {total_time:.6f} seconds\n"
        )

    print("\n================================")
    print(f"Total models: {solution_count}")
    print(f"Total time: {total_time:.4f} seconds")
    print("Done!")
    print("================================")


# ============================================================
# MAIN
# ============================================================

def main():

    if not INPUT_DIR.is_dir():
        raise FileNotFoundError(INPUT_DIR)

    input_files = sorted(INPUT_DIR.glob("*.cnf"))

    if not input_files:
        print(
            "No CNF files found in:",
            INPUT_DIR
        )
        return

    for input_file in input_files:

        banning_solution(input_file)


if __name__ == "__main__":
    main()
