"""
compress.py — Compress telemetry + audio, pick best, return bundle bytes.

Tries zlib, bz2, lzma. Verifies round-trip before selecting winner.
Bundle is self-describing so ground station decompresses without out-of-band config.
"""

import hashlib
import json
import lzma
import os
import struct
import time
import zlib
import bz2

# Bundle header: magic(8) + session_id(16) + algo_id(1) +
#   tele_raw_len(4) + tele_comp_len(4) + audio_raw_len(4) + audio_comp_len(4) +
#   sha256(32) = 73 bytes
BUNDLE_MAGIC  = b"FDRBNDL3"
BUNDLE_FMT    = "!8s16sBIIII32s"
BUNDLE_HDR_SZ = struct.calcsize(BUNDLE_FMT)

ALGO_IDS = {"zlib": 1, "bz2": 2, "lzma": 3}
ALGO_FNS = {
    "zlib": (lambda d: zlib.compress(d, 9), zlib.decompress),
    "bz2":  (lambda d: bz2.compress(d, 9),  bz2.decompress),
    "lzma": (lzma.compress,                  lzma.decompress),
}


def compress_bundle(session_id: bytes, tele_raw: bytes, audio_raw: bytes) -> bytes:
    """Compress with all algos, verify each, pick smallest, return bundle bytes."""
    results = {}
    print(f"\n{'ALGO':<8} {'IN':>10} {'OUT':>10} {'RATIO':>7} {'ms':>6}  OK")
    for name, (cfn, dfn) in ALGO_FNS.items():
        t0 = time.perf_counter()
        tc = cfn(tele_raw)
        ac = cfn(audio_raw)
        elapsed = (time.perf_counter() - t0) * 1000
        ok = (dfn(tc) == tele_raw) and (dfn(ac) == audio_raw)
        total_in  = len(tele_raw) + len(audio_raw)
        total_out = len(tc) + len(ac)
        print(f"{name:<8} {total_in:>10,} {total_out:>10,} {total_in/total_out:>7.2f}x {elapsed:>5.0f}ms  {'✓' if ok else '✗'}")
        if ok:
            results[name] = (tc, ac, total_out)

    best = min(results, key=lambda k: results[k][2])
    tc, ac, _ = results[best]
    print(f"\nSelected : {best.upper()} ({ALGO_IDS[best]})")

    integrity = hashlib.sha256(tc + ac).digest()
    header = struct.pack(BUNDLE_FMT,
        BUNDLE_MAGIC, session_id, ALGO_IDS[best],
        len(tele_raw), len(tc), len(audio_raw), len(ac), integrity)
    return header + tc + ac


def decompress_bundle(bundle: bytes) -> dict:
    """Parse + decompress bundle, verify integrity. Returns dict with tele/audio bytes."""
    if len(bundle) < BUNDLE_HDR_SZ:
        raise ValueError("Bundle too short")
    magic, session_id, algo_id, tele_raw_len, tele_comp_len, \
        audio_raw_len, audio_comp_len, stored_hash = struct.unpack_from(BUNDLE_FMT, bundle)
    if magic != BUNDLE_MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")

    # Reverse lookup algo
    id_to_name = {v: k for k, v in ALGO_IDS.items()}
    algo = id_to_name.get(algo_id)
    if algo is None:
        raise ValueError(f"Unknown algo_id {algo_id}")
    _, dfn = ALGO_FNS[algo]

    tc = bundle[BUNDLE_HDR_SZ : BUNDLE_HDR_SZ + tele_comp_len]
    ac = bundle[BUNDLE_HDR_SZ + tele_comp_len : BUNDLE_HDR_SZ + tele_comp_len + audio_comp_len]

    # Integrity check before decompressing
    actual_hash = hashlib.sha256(tc + ac).digest()
    if actual_hash != stored_hash:
        raise ValueError("SHA-256 integrity check FAILED — bundle corrupted")

    tele  = dfn(tc)
    audio = dfn(ac)

    if len(tele) != tele_raw_len:
        raise ValueError(f"Tele size mismatch: got {len(tele)}, expected {tele_raw_len}")
    if len(audio) != audio_raw_len:
        raise ValueError(f"Audio size mismatch: got {len(audio)}, expected {audio_raw_len}")

    return {
        "session_id":    session_id.hex(),
        "algo":          algo,
        "tele_raw_len":  tele_raw_len,
        "tele_comp_len": tele_comp_len,
        "audio_raw_len": audio_raw_len,
        "audio_comp_len": audio_comp_len,
        "tele":          tele,
        "audio":         audio,
    }
