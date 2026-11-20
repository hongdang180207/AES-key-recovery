from pathlib import Path
from src.approaches.banning_solution import (
    read_cnf,
    write_cnf,
    solve_with_kissat
)

source = Path("data/test/write_test.cnf")
working = Path("data/test/banning_working.cnf")

num_vars, original_clauses = read_cnf(source)
clauses = original_clauses.copy()

count = 0

while True:
    write_cnf(working, num_vars, clauses)

    status, model = solve_with_kissat(working)

    if status == "UNSAT":
        break

    count += 1
    print(f"Solution {count}: {model}")

    blocking_clause = " ".join(
        str(-literal) for literal in model
    ) + " 0"

    clauses.append(blocking_clause)

working.unlink(missing_ok=True)

print("Total models:", count)
