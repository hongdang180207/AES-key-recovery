"""Focused regression tests for the Banning Solution implementation."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.approaches.banning_solution import (
    SolveResult,
    _parse_solver_output,
    banning_solution,
    key_blocking_clause,
    model_to_binary,
    read_cnf,
    write_cnf,
)


class BanningSolutionTests(unittest.TestCase):
    def test_multiline_dimacs_read_write_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.cnf"
            target = Path(temp) / "round_trip.cnf"
            source.write_text("c comment\np cnf 3 2\n1\n2 -3\n0\n-1 3 0\n", encoding="ascii")
            num_vars, clauses = read_cnf(source)
            self.assertEqual((num_vars, clauses), (3, [[1, 2, -3], [-1, 3]]))
            write_cnf(target, num_vars, clauses)
            self.assertEqual(read_cnf(target), (num_vars, clauses))

    def test_key_bit_order_and_thesis_sign_convention(self):
        model = {var: var == 1 or var == 128 for var in range(1, 129)}
        self.assertEqual(model_to_binary(model), "1" + "0" * 126 + "1")

    def test_blocking_clause_covers_key_only(self):
        model = {var: var % 2 == 0 for var in range(1, 131)}
        clause = key_blocking_clause(model)
        self.assertEqual(len(clause), 128)
        self.assertNotIn(129, [abs(lit) for lit in clause])
        self.assertNotIn(130, [abs(lit) for lit in clause])
        self.assertEqual(clause[:4], [1, -2, 3, -4])

    def test_solver_output_parsing(self):
        sat = _parse_solver_output("s SATISFIABLE\nv 1 -2 0\n", "", 10, 0.01)
        self.assertEqual(sat.status, "SAT")
        self.assertEqual(sat.model, {1: True, 2: False})
        unsat = _parse_solver_output("s UNSATISFIABLE\n", "", 20, 0.01)
        self.assertEqual(unsat.status, "UNSAT")

    def test_enumeration_counts_distinct_keys_and_persists(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cnf = root / "tiny.cnf"
            write_cnf(cnf, 130, [[1]])
            first = {var: (var == 1) for var in range(1, 131)}
            second = {var: (var == 1 or var == 2) for var in range(1, 131)}
            responses = [
                SolveResult("SAT", first, 0.01, 10),
                SolveResult("SAT", second, 0.02, 10),
                SolveResult("UNSAT", None, 0.01, 20),
            ]
            work, solutions, timings = root / "work", root / "solutions", root / "timings"
            import src.approaches.banning_solution as module
            real_write_cnf = module.write_cnf
            clause_snapshots = []

            def capture_cnf(path, num_vars, clauses):
                clause_snapshots.append([list(clause) for clause in clauses])
                return real_write_cnf(path, num_vars, clauses)

            with patch("src.approaches.banning_solution.write_cnf", side_effect=capture_cnf), \
                 patch("src.approaches.banning_solution.solve_with_kissat", side_effect=responses) as solver:
                result = banning_solution(cnf, kissat="unused", work_dir=work,
                                          solution_dir=solutions, timing_dir=timings)
            self.assertEqual((result.status, result.solution_count, result.solver_calls), ("UNSAT", 2, 3))
            self.assertNotEqual(result.keys_hex[0], result.keys_hex[1])
            self.assertTrue((solutions / "tiny_solutions.jsonl").is_file())
            self.assertTrue((timings / "tiny_timing.json").is_file())
            self.assertEqual(solver.call_count, 3)
            self.assertEqual(len(clause_snapshots[1][-1]), 128)
            self.assertEqual({abs(lit) for lit in clause_snapshots[1][-1]}, set(range(1, 129)))
            self.assertEqual(len(clause_snapshots[2][-2]), 128)


if __name__ == "__main__":
    unittest.main()
