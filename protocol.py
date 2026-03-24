"""
protocol.py — Wire format, FEC (XOR), bitmap ACK.

Why XOR-FEC over windowed-only:
  A single parity packet per group of K data packets lets the ground recover
  one erasure without a retransmit RTT. On a lossy link (L-band, RF) where
  loss is bursty this halves recovery latency. Windowed ACK then handles
  anything FEC can't fix.

Bitmap ACK:
  Ground sends one ACK per window (K packets). A 64-bit bitmask covers
  K≤64 chunks. Aircraft retransmits only the zero bits — not everything.

Packet wire layout:
  [4B]  magic    b"FDRP"
  [16B] session  UUID bytes
  [4B]  seq      uint32 monotonic
  [2B]  chunk    uint16 index within bundle (0-based)
  [2B]  total    uint16 total data chunks (FEC parities excluded)
  [1B]  flags    bit0=FEC_PARITY, bit1=RETRANSMIT
  [4B]  fec_grp  uint32 FEC group id (chunk // FEC_K)
  [8B]  ts_ms    uint64 sender wall-clock ms
  [2B]  pay_len  uint16
  [N B] payload
  [32B] HMAC-SHA256(header + payload)

Bitmap ACK layout (ground → aircraft):
  [4B]  magic    b"BACK"
  [2B]  win_start uint16 first chunk index this bitmap covers
  [8B]  bitmap   uint64 bit-i=1 means chunk (win_start+i) received
"""

import hashlib
import struct
import time

from crypto import mac_tag, mac_verify

# Packet header
PKT_MAGIC   = b"FDRP"
PKT_FMT     = "!4s16sIHHBI Q H"   # space for readability
PKT_HDR_SZ  = struct.calcsize(PKT_FMT)
HMAC_SZ     = 32
FLAG_PARITY = 0x01
FLAG_RETX   = 0x02

# Bitmap ACK
ACK_MAGIC   = b"BACK"
ACK_FMT     = "!4sHQ"
ACK_SZ      = struct.calcsize(ACK_FMT)

FEC_K       = 8    # one parity per K data packets


def make_packet(session: bytes, seq: int, chunk: int, total: int,
                payload: bytes, flags: int = 0, fec_grp: int = 0) -> bytes:
    ts_ms  = int(time.time() * 1000)
    header = struct.pack(PKT_FMT, PKT_MAGIC, session, seq,
                         chunk, total, flags, fec_grp, ts_ms, len(payload))
    tag = mac_tag(header + payload)
    return header + payload + tag


def parse_packet(data: bytes):
    """Verify HMAC, return (fields_dict, payload) or raise ValueError."""
    min_sz = PKT_HDR_SZ + HMAC_SZ
    if len(data) < min_sz:
        raise ValueError(f"Too short: {len(data)}")
    pay_len = struct.unpack_from("!H", data, PKT_HDR_SZ - 2)[0]
    total_expected = PKT_HDR_SZ + pay_len + HMAC_SZ
    if len(data) < total_expected:
        raise ValueError("Truncated")
    header  = data[:PKT_HDR_SZ]
    payload = data[PKT_HDR_SZ : PKT_HDR_SZ + pay_len]
    tag     = data[PKT_HDR_SZ + pay_len : PKT_HDR_SZ + pay_len + HMAC_SZ]
    if not mac_verify(header + payload, tag):
        raise ValueError("HMAC mismatch")
    magic, session, seq, chunk, total, flags, fec_grp, ts_ms, _ = \
        struct.unpack_from(PKT_FMT, header)
    return {
        "session": session, "seq": seq, "chunk": chunk,
        "total": total, "flags": flags, "fec_grp": fec_grp,
        "ts_ms": ts_ms, "wire_bytes": len(data),
    }, payload


def make_ack(win_start: int, bitmap: int) -> bytes:
    return struct.pack(ACK_FMT, ACK_MAGIC, win_start, bitmap)


def parse_ack(data: bytes):
    """Return (win_start, bitmap) or raise ValueError."""
    if len(data) < ACK_SZ or data[:4] != ACK_MAGIC:
        raise ValueError("Bad ACK")
    _, win_start, bitmap = struct.unpack_from(ACK_FMT, data)
    return win_start, bitmap


def fec_parity(group_payloads: list) -> bytes:
    """XOR all payloads in a group. All must be same length (pad shorter ones)."""
    max_len = max(len(p) for p in group_payloads)
    result  = bytearray(max_len)
    for p in group_payloads:
        padded = p + bytes(max_len - len(p))
        for i in range(max_len):
            result[i] ^= padded[i]
    return bytes(result)


def fec_recover(group_payloads: dict, total_in_group: int, parity: bytes) -> bytes:
    """
    Recover one missing payload from XOR parity.
    group_payloads: {idx: bytes} for all present chunks in group.
    Returns recovered bytes or raises ValueError if >1 missing.
    """
    present = set(group_payloads.keys())
    all_idx = set(range(total_in_group))
    missing = all_idx - present
    if len(missing) != 1:
        raise ValueError(f"FEC can only recover 1 erasure, {len(missing)} missing")
    result = bytearray(parity)
    for p in group_payloads.values():
        padded = p + bytes(len(result) - len(p))
        for i in range(len(result)):
            result[i] ^= padded[i]
    return bytes(result)


def chunks_to_packets(session: bytes, data: bytes, chunk_size: int):
    """
    Split data into chunks, add FEC parity packets.
    Yields (chunk_idx, total_data_chunks, payload, flags, fec_grp).
    Parity packets have flags=FLAG_PARITY and chunk_idx = group boundary.
    """
    raw_chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    total      = len(raw_chunks)
    seq        = 0

    for grp_start in range(0, total, FEC_K):
        grp_end   = min(grp_start + FEC_K, total)
        grp_data  = raw_chunks[grp_start:grp_end]
        grp_id    = grp_start // FEC_K

        for local_i, payload in enumerate(grp_data):
            idx = grp_start + local_i
            yield idx, total, payload, 0, grp_id

        # One XOR parity packet per group
        parity = fec_parity(grp_data)
        yield grp_start, total, parity, FLAG_PARITY, grp_id
