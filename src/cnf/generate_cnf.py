"""Generate reproducible AES-128 key-schedule recovery DIMACS instances.

The default observation pattern matches the thesis experiments: the first 60
bits of round key 1 and the last 60 bits of round key 10 are known. Both
standard DIMACS and CryptoMiniSat XOR-CNF encodings are emitted.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

try:
    from .aeskeyschedule2 import SBOX, key_schedule
except ImportError:  # direct execution: python src/cnf/generate_cnf.py
    from aeskeyschedule2 import SBOX, key_schedule


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STANDARD_DIR = PROJECT_ROOT / "data" / "cnf" / "standard"
DEFAULT_XOR_DIR = PROJECT_ROOT / "data" / "cnf" / "xor"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "test" / "manifest.json"


@dataclass
class AES128CNF:
    num_vars: int
    clauses: list[list[int]]
    xor_equations: list[list[int]]
    round_key_variables: list[list[int]]
    observations: dict[str, int]


def _sbox_clauses(inputs: Sequence[int], outputs: Sequence[int]) -> list[list[int]]:
    """Encode y = AES_SBOX(x) as 256x8 guarded output clauses."""
    if len(inputs) != 8 or len(outputs) != 8:
        raise ValueError("AES S-box encoding needs eight input and output bits")
    clauses: list[list[int]] = []
    for value, substituted in enumerate(SBOX):
        in_bits = [(value >> (7 - bit)) & 1 for bit in range(8)]
        guard = [var if bit == 0 else -var for var, bit in zip(inputs, in_bits)]
        for bit_index, var in enumerate(outputs):
            expected = (substituted >> (7 - bit_index)) & 1
            clauses.append(guard + [var if expected else -var])
    return clauses


def xor_equation_to_cnf(signed_variables: Sequence[int]) -> list[list[int]]:
    """Encode XOR of signed literals == 1 using the forbidden even parities."""
    if not signed_variables or len(set(abs(v) for v in signed_variables)) != len(signed_variables):
        raise ValueError("XOR equation needs distinct nonzero variables")
    width = len(signed_variables)
    clauses: list[list[int]] = []
    for assignment in range(1 << width):
        # The signed-literal parity is even, so the assignment is forbidden.
        if assignment.bit_count() & 1:
            continue
        clause: list[int] = []
        for position, signed_var in enumerate(signed_variables):
            literal_value = (assignment >> position) & 1
            var_value = literal_value ^ (signed_var < 0)
            variable = abs(signed_var)
            clause.append(variable if var_value == 0 else -variable)
        clauses.append(clause)
    return clauses


def generate_aes128_cnf(
    key: bytes,
    *,
    round1_known_bits: int = 60,
    round10_known_bits: int = 60,
) -> AES128CNF:
    """Build schedule constraints and the thesis-style known-bit units."""
    if len(key) != 16:
        raise ValueError("The recovery generator currently supports AES-128 keys only")
    if not 0 <= round1_known_bits <= 128 or not 0 <= round10_known_bits <= 128:
        raise ValueError("Known-bit counts must be in 0..128")

    next_var = 1
    round_key_variables: list[list[int]] = [list(range(1, 129))]
    next_var = 129
    clauses: list[list[int]] = []
    xor_equations: list[list[int]] = []
    round_keys = key_schedule(key)

    for round_index in range(1, 11):
        # Preserve the thesis variable layout: a 32-bit SubWord output is
        # allocated before the 128-bit round key (e.g. round 1 starts at 161).
        sbox_result = list(range(next_var, next_var + 32))
        next_var += 32
        this_round_vars = list(range(next_var, next_var + 128))
        next_var += 128
        round_key_variables.append(this_round_vars)

        previous = round_key_variables[round_index - 1]
        # RotWord on the last word: byte order [1,2,3,0], MSB-first per byte.
        last_word = previous[96:128]
        rotated = last_word[8:16] + last_word[16:24] + last_word[24:32] + last_word[0:8]
        for byte_index in range(4):
            clauses.extend(_sbox_clauses(rotated[byte_index*8:(byte_index+1)*8],
                                         sbox_result[byte_index*8:(byte_index+1)*8]))

        # AES Rcon uses the standard sequence 01,02,04,08,10,20,40,80,1B,36.
        rcon_values = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
        rcon_word = rcon_values[round_index - 1] << 24

        for bit_index in range(32):
            a = previous[bit_index]
            b = sbox_result[bit_index]
            out = this_round_vars[bit_index]
            constant = (rcon_word >> (31 - bit_index)) & 1
            # a XOR b XOR out = Rcon_bit, represented as XOR(signed lits)=1.
            xor_equations.append([a, b, out] if constant else [a, b, -out])

        for word_index in range(1, 4):
            for bit_index in range(32):
                a = previous[word_index * 32 + bit_index]
                b = this_round_vars[(word_index - 1) * 32 + bit_index]
                out = this_round_vars[word_index * 32 + bit_index]
                xor_equations.append([a, b, -out])

    # Add the thesis image observations to round keys 1 and 10.
    observations: dict[str, int] = {}
    for round_index, bit_indices in (
        (1, range(round1_known_bits)),
        (10, range(128 - round10_known_bits, 128)),
    ):
        for bit_index in bit_indices:
            variable = round_key_variables[round_index][bit_index]
            bit_value = int(f"{int.from_bytes(round_keys[round_index], 'big'):0128b}"[bit_index])
            clauses.append([variable if bit_value else -variable])
            observations[f"r{round_index}_b{bit_index}"] = bit_value

    # All generated variables have a role; each round uses 32 S-box temporary
    # bits and 128 output bits, producing the original 1728-variable layout.
    return AES128CNF(next_var - 1, clauses, xor_equations,
                     round_key_variables, observations)


def _standard_clauses(instance: AES128CNF) -> list[list[int]]:
    result = list(instance.clauses)
    for equation in instance.xor_equations:
        result.extend(xor_equation_to_cnf(equation))
    return result


def write_dimacs(path: str | Path, num_vars: int, clauses: Iterable[Sequence[int]]) -> None:
    clauses = [list(clause) for clause in clauses]
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="\n") as stream:
        stream.write(f"p cnf {num_vars} {len(clauses)}\n")
        for clause in clauses:
            stream.write(" ".join(map(str, clause)) + " 0\n")


def write_xcnf(path: str | Path, num_vars: int, clauses: Iterable[Sequence[int]],
               xor_equations: Iterable[Sequence[int]]) -> None:
    clauses, xor_equations = list(clauses), list(xor_equations)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="\n") as stream:
        stream.write(f"p cnf {num_vars} {len(clauses) + len(xor_equations)}\n")
        for clause in clauses:
            stream.write(" ".join(map(str, clause)) + " 0\n")
        for equation in xor_equations:
            stream.write("x" + str(equation[0]) + " "
                         + " ".join(map(str, equation[1:])) + " 0\n")


def generate_dataset(count: int, *, seed: int = 1, standard_dir: str | Path = DEFAULT_STANDARD_DIR,
                     xor_dir: str | Path = DEFAULT_XOR_DIR, manifest: str | Path = DEFAULT_MANIFEST,
                     round1_known_bits: int = 60, round10_known_bits: int = 60,
                     formats: str = "both") -> list[dict]:
    if count < 1:
        raise ValueError("count must be positive")
    rng = random.Random(seed)
    records = []
    for index in range(count):
        key = bytes(rng.randrange(256) for _ in range(16))
        instance = generate_aes128_cnf(key, round1_known_bits=round1_known_bits,
                                       round10_known_bits=round10_known_bits)
        name = f"aes128_{index:03d}.cnf"
        if formats in ("standard", "both"):
            write_dimacs(Path(standard_dir) / name, instance.num_vars, _standard_clauses(instance))
        if formats in ("xor", "both"):
            write_xcnf(Path(xor_dir) / name, instance.num_vars, instance.clauses,
                       instance.xor_equations)
        records.append({
            "name": name,
            "ground_truth_key_hex": key.hex(),
            "num_vars": instance.num_vars,
            "standard_clause_count": len(instance.clauses) + len(instance.xor_equations) * 4,
            "xor_clause_count": len(instance.clauses) + len(instance.xor_equations),
            "observed_bit_count": len(instance.observations),
            "seed": seed,
        })
        print(f"Generated {name}: vars={instance.num_vars}, "
              f"known_bits={len(instance.observations)}", flush=True)
    manifest_path = Path(manifest)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({"seed": seed, "datasets": records}, indent=2) + "\n",
                             encoding="utf-8")
    return records


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--round1-known-bits", type=int, default=60)
    parser.add_argument("--round10-known-bits", type=int, default=60)
    parser.add_argument("--format", choices=("standard", "xor", "both"), default="both")
    parser.add_argument("--standard-dir", type=Path, default=DEFAULT_STANDARD_DIR)
    parser.add_argument("--xor-dir", type=Path, default=DEFAULT_XOR_DIR)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args(argv)
    generate_dataset(args.count, seed=args.seed, standard_dir=args.standard_dir,
                     xor_dir=args.xor_dir, manifest=args.manifest,
                     round1_known_bits=args.round1_known_bits,
                     round10_known_bits=args.round10_known_bits, formats=args.format)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
