# AES key recovery

## Banning Solution (Kissat)

`src/approaches/banning_solution.py` reads standard DIMACS CNF and enumerates
distinct AES-128 keys. It expects the original-key bits in variables 1 through
128, in order. A key blocking clause contains only those 128 variables, so
different assignments to auxiliary variables cannot make the same key appear
again. The positive/negative model convention follows the thesis generator:
positive literal means key bit `1`.

Run one dataset from the repository root:

```powershell
python -m src.approaches.banning_solution "test/0 output.cnf" --kissat solvers/kissat/build/kissat
```

For all ten appendix datasets:

```powershell
python -m src.approaches.banning_solution "test/0 output.cnf" "test/1 output.cnf" "test/2 output.cnf" "test/3 output.cnf" "test/4 output.cnf" "test/5 output.cnf" "test/6 output.cnf" "test/7 output.cnf" "test/8 output.cnf" "test/9 output.cnf" --timeout 3600
```

The timeout applies to each Kissat call. Use `--max-solutions N` to stop after
N distinct keys. Kissat must be executable on the host (the checked-in build
artifact is Linux ELF, so Windows needs a Windows Kissat build or a Linux
environment such as WSL).

Results are written under `results/solutions/` as JSON Lines and
`results/timings/` as JSON, including the terminal status (`UNSAT`, `TIMEOUT`,
`UNKNOWN`, or `LIMIT_REACHED`), keys found, solver-call count, and elapsed time.
Temporary working CNF files are placed in `results/logs/` and removed at the
end of each run.
