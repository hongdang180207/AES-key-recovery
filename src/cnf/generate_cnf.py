from sage.crypto.sboxes import AES
import random
import io
from aeskeyschedule2 import getSchedule
import os
import binascii
from random import randbytes
from platform import release

varcounter = 1
outfile = "outputXor.cnf"
kwowbit = 60


def newvars():
    global varcounter
    n = [j for j in range(varcounter, varcounter + 32)]
    varcounter += 32
    return n


def AssignRoundKey(Words, KeyValue, KeyRound, Start, End):
    baseKey = Words[KeyRound * N][0]
    KeyWords = []

    for w in Words[KeyRound * N:(KeyRound + 1) * N]:
        KeyWords += w

    for i in range(Start, End):
        assert baseKey + i == KeyWords[i]

        if KeyValue[i] == '1':
            Model2.append(f'{baseKey + i} 0')
        else:
            Model2.append(f'-{baseKey + i} 0')


Words = []
Model = []
Model2 = []

N = 4
R = 10

Bcon = [
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36
]
Rcon = [''] + [f'{x:08b}' + '0' * 24 for x in Bcon]


for i in range((R + 1) * N):
    if i < N:
        Words.append(newvars())

    elif i % N == 0:
        rot = Words[-1][8:] + Words[-1][:8]
        n1 = newvars()
        n2 = newvars()

        for j in range(N):
            Model += (
                AES.cnf(
                    xi=rot[j * 8:(j + 1) * 8],
                    yi=n1[j * 8:(j + 1) * 8],
                    format='dimacs_headless'
                ).split('\n')[:-1]
            )

        for b in range(32):
            if Rcon[i // N][b] == '1':
                Model.append(
                    f'x{Words[-N][b]} {n1[b]} {n2[b]} 0'
                )
            else:
                Model.append(
                    f'x{Words[-N][b]} {n1[b]} -{n2[b]} 0'
                )

        Words.append(n2)

    else:
        n2 = newvars()

        for b in range(32):
            Model.append(
                f'x{Words[-N][b]} {Words[-1][b]} -{n2[b]} 0'
            )

        Words.append(n2)


for i in range(10):
    print("File " + str(i) + " ...")
    Model2 = []

    Bytekey = randbytes(16)
    keyschedule = getSchedule(0, Bytekey)

    Bkey = bin(int(keyschedule[0], 16))[2:]
    Bkey = Bkey.zfill(128)

    Bkey1 = bin(int(keyschedule[1], 16))[2:]
    Bkey1 = Bkey1.zfill(128)

    Bkey10 = bin(int(keyschedule[10], 16))[2:]
    Bkey10 = Bkey10.zfill(128)

    AssignRoundKey(Words, Bkey1, 1, 0, kwowbit)
    AssignRoundKey(Words, Bkey10, 10, 128 - kwowbit, 128)

    f = open(
        "test/" + str(i) + outfile,
        'w',
        encoding='utf-8'
    )
    f.write(
        f'p cnf {varcounter - 1} {len(Model) + len(Model2)}\n'
    )

    for c in Model:
        f.write(c + '\n')

    for c in Model2:
        f.write(c + '\n')

    f.close()

    f = io.open(
    "test/" + str(i) + outfile,
    "r",
    newline='\n'
    )
    allOfIt = f.readlines()
    f.close()

    cnfClause = []
    xorClause = []

    # Separate normal CNF clauses and XOR clauses
    for line in allOfIt:
        if line.strip().startswith("x"):
            xorClause.append(line)
        elif not line.startswith("p"):
            cnfClause.append(line)

    # Convert each 3-literal XOR clause into 4 CNF clauses
    for line in xorClause:
        tokens = line.strip().split()

        # Example: x1 129 -161 0
        literals = [
            int(tokens[0][1:]),
            int(tokens[1]),
            int(tokens[2])
        ]

        if len(tokens) != 4 or tokens[3] != "0":
            raise ValueError(f"Invalid XOR clause: {line}")

        if len(literals) != 3:
            raise ValueError(f"Expected 3 literals: {line}")

        # XOR = 1: exclude the four even-parity assignments
        assignments = [
            (0, 0, 0),
            (0, 1, 1),
            (1, 0, 1),
            (1, 1, 0)
        ]

        for assignment in assignments:
            clause = [
                literal if bit == 0 else -literal
                for literal, bit in zip(literals, assignment)
            ]

            cnfClause.append(
                " ".join(map(str, clause)) + " 0\n"
            )

    # Update DIMACS header
    cnfClause.insert(
        0,
        f'p cnf {varcounter - 1} {len(cnfClause)}\n'
    )

    f = open(
        "test/" + str(i) + " output.cnf",
        'w',
        newline='\n'
    )

    for x in cnfClause:
        f.write(x)

    f.close()

    # for print solution of CNF
    # f = open(str(i) + " solution.txt", 'w', newline='\n')
    # f.write(Bkey)
    # f.close()

    # in case you don't need xor cnf de-comment the next line
    # os.remove(str(i) + " outputXor.cnf")

print("Done!")
