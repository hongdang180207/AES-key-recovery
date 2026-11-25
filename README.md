# AES key recovery

Python code for reproducing the AES-128 partial key-schedule recovery approaches
from the thesis appendix. It has no Sage dependency. The CNF generator emits
standard DIMACS for Kissat and CryptoMiniSat XOR-CNF for native XOR solving.

## Generate the ten benchmark instances

From the repository root on Linux:

```bash
python3 -m src.cnf.generate_cnf --count 10 --seed 1 --format both
```

The default observation pattern matches the appendix: the first 60 bits of
round key 1 and the last 60 bits of round key 10. Files are written to
`data/cnf/standard/` and `data/cnf/xor/`. `data/test/manifest.json` records the
seed and generated ground-truth keys for result checking. The standard format
can be solved by Kissat; the `x... 0` format needs CryptoMiniSat.

## Build the solvers on Linux

Initialize the solver submodules if needed, then build Kissat:

```bash
git submodule update --init --recursive
cd solvers/kissat
./configure
make -j"$(nproc)"
cd ../..
```

Build CryptoMiniSat with CMake when you want to use the XOR datasets:

```bash
cmake -S solvers/cryptominisat -B solvers/cryptominisat/build
cmake --build solvers/cryptominisat/build -j"$(nproc)"
```

The runner expects the resulting executables at `solvers/kissat/build/kissat`
and `solvers/cryptominisat/build/cryptominisat5`; pass `--solver-path` if your
build places either executable elsewhere.

The generator preserves the appendix's variable layout: 1,728 variables, with
the master key in variables 1-128 and round-key output bits in the corresponding
schedule ranges. AES S-boxes use a truth-table CNF encoding; each XOR relation is
expanded to four clauses for standard DIMACS.

## Run the four approaches

The default solver paths are `solvers/kissat/build/kissat` and
`solvers/cryptominisat/build/cryptominisat5`. Use `--solver-path` if your binary
is elsewhere. `--timeout` limits each solver call; `--overall-timeout` limits
the whole approach run.

### Banning Solution

Enumerates unique master keys and blocks only variables 1-128. It prints a line
before every solver call and saves each key immediately.

```bash
python3 -m src.approaches.banning_solution data/cnf/standard/aes128_000.cnf --timeout 3600
```

For XOR-CNF, choose CryptoMiniSat:

```bash
python3 -m src.approaches.banning_solution data/cnf/xor/aes128_000.cnf --solver cryptominisat --xor --timeout 3600
```

### Brute Force

The `schedule` strategy enumerates every completion of the most-known observed
round key, reverses it to the AES master key and checks all observed schedule
bits. With the default 60+60-bit images, the selected round key has 68 missing
bits, so the direct search space is `2^68`.

```bash
python3 -m src.approaches.brute_force data/cnf/standard/aes128_000.cnf --max-candidates 1000000
```

`--strategy thesis-sat` reproduces the appendix's SAT-assisted enumeration: it
splits `--infer-bits` evenly across unknown portions of round keys 1 and 10,
then makes one solver call for each assignment and checks the returned key
against the AES schedule.

```bash
python3 -m src.approaches.brute_force data/cnf/standard/aes128_000.cnf --strategy thesis-sat --infer-bits 8 --solver kissat
```

### Mixed Approach

Uses the same split round-1/round-10 guesses as the appendix, then runs the
Banning Solution loop under every assignment.

```bash
python3 -m src.approaches.mixed_approach data/cnf/standard/aes128_000.cnf --infer-bits 8 --timeout 3600
```

### Random Bit Instancing

Randomly selects currently unobserved round-key output variables, enumerates
all `2^sample_bits` assignments to that selected subset, and uses the Banning
Solution loop for each assignment. `--seed` makes the selected subsets
reproducible.

```bash
python3 -m src.approaches.random_instancing data/cnf/standard/aes128_000.cnf --sample-bits 8 --seed 1 --timeout 3600
```

For native XOR-CNF, pass `--solver cryptominisat --xor` to Banning, Mixed, or
Random Instancing. Brute Force also accepts `--xor`; its `thesis-sat` strategy
uses the same solver options.

## Run a shared comparison

The batch runner uses the same input files for all selected methods, records
SAT calls, statuses, recovered keys, and runtimes, then writes JSON and CSV
summaries. It defaults to the appendix-style SAT-assisted Brute Force variant;
`--brute-mode schedule` selects the standalone `2^unknown_bits` key-schedule
enumeration.

```bash
python3 -m src.approaches.run_experiments \
  --input-dir data/cnf/standard --pattern 'aes128_*.cnf' \
  --methods banning,brute_force,mixed,random_instancing \
  --brute-mode thesis-sat --infer-bits 8 --random-bits 8 \
  --timeout 3600 --overall-timeout 86400
```

To compare XOR-CNF instead, use `--input-dir data/cnf/xor --xor
--solver cryptominisat`. Optional caps (`--max-assignments` and
`--max-solutions`) are recorded in each approach's run status and should be
kept the same across datasets when comparing methods.

## Results

Each method writes JSON Lines containing recovered keys under
`results/solutions/`, per-run JSON summaries under `results/timings/`, and
per-call or per-instance traces under `results/logs/`. Statuses distinguish
complete enumeration from timeouts, interrupted runs, and user-set limits.

The methods are intentionally allowed to return multiple valid keys when the
partial schedule does not uniquely determine the master key. Compare those
keys against the generated manifest rather than treating a second SAT model as
a different key unless its 128-bit master-key value differs.
