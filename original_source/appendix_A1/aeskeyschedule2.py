import argparse
from binascii import hexlify, unhexlify

from aeskeyschedule import key_schedule, reverse_key_schedule

import sys

try:
    import colorama
    colorama.init()
    __highlight = colorama.Style.BRIGHT
    __reset = colorama.Style.RESET_ALL
except ImportError:
    __highlight = ''
    __reset = ''


def aes_round(value: str) -> int:
    aes_round = int(value)
    if not 0 <= aes_round <= 10:
        raise argparse.ArgumentError(
            'the aes round must satisfy 0 <= r <= 10'
        )
    return aes_round


def aes_key(value: str) -> bytes:
    if value.startswith('0x'):
        value = value[2:]

    try:
        key = unhexlify(value)
    except TypeError:
        raise argparse.ArgumentError('invalid hex bytes in aes key')

    if len(key) * 8 not in {128, 192, 256}:
        raise argparse.ArgumentError(
            '''
            AES key must be 128, 192 or 256 bits long (is {} bits)
            '''.strip().format(len(key) * 8)
        )

    return key


def getSchedule(aes_round: int, round_key: bytes) -> list:
    if len(round_key) * 8 != 128 and aes_round != 0:
        print(
            "reversing the AES-{} key schedule is not supported".format(
                len(round_key) * 8
            ),
            file=sys.stderr
        )
        sys.exit(1)

    if aes_round != 0:
        base_key = reverse_key_schedule(round_key, aes_round)
    else:
        base_key = round_key

    keys = key_schedule(base_key)

    assert keys[aes_round] == round_key or len(base_key) * 8 != 128

    total = []

    for i, key in enumerate(keys):
        if i == aes_round:
            print(__highlight, end='')

        total.append(hexlify(key).decode())

        if i == aes_round:
            print(__reset, end='')

    return total


print(
    getSchedule(
        0,
        b'00000000000000000000000000000000'
    )
)
