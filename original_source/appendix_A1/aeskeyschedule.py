from typing import List
from functools import reduce


def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8), using the AES polynomial."""
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        high_bit = a & 0x80
        a = (a << 1) & 0xFF

        if high_bit:
            a ^= 0x1B

        b >>= 1

    return result


def gf_pow(a: int, power: int) -> int:
    result = 1

    while power:
        if power & 1:
            result = gf_mul(result, a)

        a = gf_mul(a, a)
        power >>= 1

    return result


def rot_byte(value: int, count: int) -> int:
    return (
        (value << count) | (value >> (8 - count))
    ) & 0xFF


def generate_sbox() -> List[int]:
    table = []

    for value in range(256):
        inverse = 0 if value == 0 else gf_pow(value, 254)

        substituted = (
            inverse
            ^ rot_byte(inverse, 1)
            ^ rot_byte(inverse, 2)
            ^ rot_byte(inverse, 3)
            ^ rot_byte(inverse, 4)
            ^ 0x63
        )

        table.append(substituted)

    return table


sbox = generate_sbox()

inv_sbox = [0] * 256
for index, value in enumerate(sbox):
    inv_sbox[value] = index


rcon = [
    x.to_bytes(4, 'little')
    for x in [
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36
    ]
]


def xor_bytes(*args: bytes) -> bytes:
    assert len({len(x) for x in args}) == 1
    xor_fun = lambda x, y: x ^ y

    return bytes(
        reduce(xor_fun, byte_group)
        for byte_group in zip(*args)
    )


def rot_word(word: bytes) -> bytes:
    """
    Apply the RotWord transformation to a 4-byte word.
    """
    assert len(word) == 4
    return bytes(word[(i + 1) % 4] for i in range(4))


def inv_rot_word(word: bytes) -> bytes:
    """
    Apply the inverse RotWord transformation to a 4-byte word.
    """
    assert len(word) == 4
    return bytes(word[(i - 1) % 4] for i in range(4))


def sub_word(word: bytes) -> bytes:
    """
    Apply the AES S-box to each byte of a 4-byte word.
    """
    assert len(word) == 4
    return bytes(sbox[w] for w in word)


def inv_sub_word(word: bytes) -> bytes:
    """
    Apply the inverse AES S-box to each byte of a 4-byte word.
    """
    assert len(word) == 4
    return bytes(inv_sbox[w] for w in word)


def reverse_key_schedule(round_key: bytes, aes_round: int):
    """
    Reverse the AES-128 key schedule, using a single round key.
    """
    assert len(round_key) * 8 == 128

    for i in range(aes_round - 1, -1, -1):
        a2 = round_key[0:4]
        b2 = round_key[4:8]
        c2 = round_key[8:12]
        d2 = round_key[12:16]

        d1 = xor_bytes(d2, c2)
        c1 = xor_bytes(c2, b2)
        b1 = xor_bytes(b2, a2)
        a1 = xor_bytes(
            a2,
            rot_word(sub_word(d1)),
            rcon[i]
        )

        round_key = a1 + b1 + c1 + d1

    return round_key


def key_schedule(base_key: bytes) -> List[bytes]:
    """
    Calculate the expanded AES key given the base key.
    Depending on the length of the base key, 11, 13 or
    15 round keys are returned for AES-128, AES-192
    and AES-256 respectively.
    """
    assert len(base_key) * 8 in {128, 192, 256}

    # Length of the key in 32-bit words
    N = {128: 4, 192: 6, 256: 8}[len(base_key) * 8]

    # Number of round keys needed
    R = {128: 11, 192: 13, 256: 15}[len(base_key) * 8]

    # The 32-bit words of the expanded key
    W = [None for _ in range(R * 4)]

    for i in range(N):
        W[i] = base_key[i * 4:(i + 1) * 4]

    for i in range(N, 4 * R):
        if i % N == 0:
            W[i] = xor_bytes(
                W[i - N],
                sub_word(rot_word(W[i - 1])),
                rcon[i // N - 1]
            )
        elif N > 6 and i % N == 4:
            W[i] = xor_bytes(
                W[i - N],
                sub_word(W[i - 1])
            )
        else:
            W[i] = xor_bytes(W[i - N], W[i - 1])

    keys = [
        b''.join(W[i * 4 + j] for j in range(4))
        for i in range(R)
    ]

    return keys
