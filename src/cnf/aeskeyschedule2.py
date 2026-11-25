"""Small dependency-free AES key-schedule implementation (AES-128/192/256)."""

from __future__ import annotations

import argparse
from binascii import unhexlify
from functools import reduce


def gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return result


def gf_pow(a: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        exponent >>= 1
    return result


def _rotl8(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _make_sbox() -> tuple[int, ...]:
    values = []
    for value in range(256):
        inverse = 0 if value == 0 else gf_pow(value, 254)
        values.append(inverse ^ _rotl8(inverse, 1) ^ _rotl8(inverse, 2)
                      ^ _rotl8(inverse, 3) ^ _rotl8(inverse, 4) ^ 0x63)
    return tuple(values)


SBOX = _make_sbox()
INV_SBOX = tuple(SBOX.index(i) for i in range(256))
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D, 0x9A)


def xor_bytes(*values: bytes) -> bytes:
    if not values or len({len(value) for value in values}) != 1:
        raise ValueError("xor_bytes needs equally sized byte strings")
    return bytes(reduce(int.__xor__, group) for group in zip(*values))


def rot_word(word: bytes) -> bytes:
    if len(word) != 4:
        raise ValueError("AES words are four bytes")
    return word[1:] + word[:1]


def inv_rot_word(word: bytes) -> bytes:
    if len(word) != 4:
        raise ValueError("AES words are four bytes")
    return word[-1:] + word[:-1]


def sub_word(word: bytes) -> bytes:
    return bytes(SBOX[value] for value in word)


def inv_sub_word(word: bytes) -> bytes:
    return bytes(INV_SBOX[value] for value in word)


def key_schedule(base_key: bytes) -> list[bytes]:
    """Return AES round keys in byte order, including the original key."""
    if len(base_key) not in (16, 24, 32):
        raise ValueError("AES key length must be 16, 24 or 32 bytes")
    nk = len(base_key) // 4
    nr = nk + 6
    words = [base_key[4*i:4*i+4] for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = words[i - 1]
        if i % nk == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), bytes([RCON[i // nk - 1], 0, 0, 0]))
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        words.append(xor_bytes(words[i - nk], temp))
    return [b"".join(words[4*r:4*r+4]) for r in range(nr + 1)]


def reverse_key_schedule(round_key: bytes, aes_round: int) -> bytes:
    """Recover the AES-128 master key from one complete round key."""
    if len(round_key) != 16 or not 0 <= aes_round <= 10:
        raise ValueError("Reverse schedule requires a 16-byte AES-128 round key and round 0..10")
    words = [round_key[i:i+4] for i in range(0, 16, 4)]
    for round_index in range(aes_round - 1, -1, -1):
        a2, b2, c2, d2 = words
        d1 = xor_bytes(d2, c2)
        c1 = xor_bytes(c2, b2)
        b1 = xor_bytes(b2, a2)
        a1 = xor_bytes(a2, sub_word(rot_word(d1)), bytes([RCON[round_index], 0, 0, 0]))
        words = [a1, b1, c1, d1]
    return b"".join(words)


def getSchedule(aes_round: int, round_key: bytes | str) -> list[str]:
    """Thesis-compatible API: return round keys as lowercase hexadecimal."""
    if isinstance(round_key, str):
        value = round_key.removeprefix("0x")
        try:
            round_key = unhexlify(value)
        except (ValueError, TypeError) as exc:
            raise ValueError("round_key must be valid hexadecimal") from exc
    if not 0 <= aes_round <= 10:
        raise ValueError("AES-128 round must be between 0 and 10")
    if len(round_key) == 16:
        base_key = reverse_key_schedule(round_key, aes_round) if aes_round else round_key
    elif aes_round == 0 and len(round_key) in (24, 32):
        base_key = round_key
    else:
        raise ValueError("AES-192/256 are supported only from the master key (round 0)")
    keys = key_schedule(base_key)
    if keys[aes_round] != round_key:
        raise ValueError("Provided round key does not match the derived schedule")
    return [key.hex() for key in keys]


def aes_round(value: str) -> int:
    number = int(value)
    if not 0 <= number <= 10:
        raise argparse.ArgumentTypeError("round must be in range 0..10")
    return number


def aes_key(value: str) -> bytes:
    try:
        result = unhexlify(value.removeprefix("0x"))
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("key must be valid hexadecimal") from exc
    if len(result) not in (16, 24, 32):
        raise argparse.ArgumentTypeError("AES key must be 16, 24 or 32 bytes")
    return result


__all__ = ["SBOX", "INV_SBOX", "RCON", "gf_mul", "xor_bytes", "rot_word",
           "sub_word", "key_schedule", "reverse_key_schedule", "getSchedule"]
