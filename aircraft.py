#!/usr/bin/env python3
"""
aircraft.py — Aircraft sender.

Pipeline:
  1. Generate telemetry (200 params) + CVR audio
  2. Compress (auto-picks best algo, verifies round-trip)
  3. Sign bundle: ECDSA P-256 + lattice LWE (both, with timing comparison)
  4. Packetize with XOR-FEC (one parity per 8 data chunks)
  5. Send to ALL configured ground stations; any one ACK is sufficient
  6. DTN store-and-forward:
       - Unacknowledged chunks persisted to disk every cycle
       - Exponential backoff: 1s → 2s → 4s → ... cap 30s, max 10 retries
       - On restart, resumes from saved state (no re-send of ACKed chunks)
       - time.sleep(0.5) per packet so you can kill the ground and watch
  7. Bitmap ACK: retransmit only missing chunks, not entire window

Run:
  Terminal 1:  python3 ground.py --port 9000 --name GS-Primary
  Terminal 2:  python3 ground.py --port 9001 --name GS-Backup
  Terminal 3:  python3 aircraft.py
  Kill one ground station mid-flight, restart it — aircraft resumes.
"""

import json
import os
import socket
import struct
import sys
import time
import uuid
import wave

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config as cfg
from telemetry   import generate_telemetry, generate_audio
from compress    import compress_bundle, decompress_bundle, BUNDLE_HDR_SZ
from crypto      import (ecdsa_keygen, ecdsa_sign, ecdsa_verify,
                          save_ecdsa_keys, load_ecdsa_private, load_ecdsa_public,
                          LatticeKey, benchmark)
from protocol    import (make_packet, parse_ack, chunks_to_packets,
                          FEC_K, FLAG_PARITY, FLAG_RETX, ACK_MAGIC)

os.makedirs("output", exist_ok=True)
os.makedirs("keys", exist_ok=True)


# ── Key setup (run once; idempotent) ─────────────────────────────────────────

def ensure_keys():
    if not os.path.exists(cfg.PRIVATE_KEY_PATH):
        priv, pub = ecdsa_keygen()
        save_ecdsa_keys(priv, pub)
        print(f"Keys generated → {cfg.PRIVATE_KEY_PATH}")
        print(f"  Copy {cfg.PUBLIC_KEY_PATH} to ground station keys/ folder")
    return load_ecdsa_private()


# ── DTN state: persisted to disk between runs ─────────────────────────────────

def load_dtn_state() -> dict:
    """Returns {session_id, bundle_hash, acked_chunks: set, retry_count: dict}."""
    if os.path.exists(cfg.DTN_STATE_FILE):
        with open(cfg.DTN_STATE_FILE) as f:
            raw = json.load(f)
        raw["acked_chunks"] = set(raw.get("acked_chunks", []))
        raw["retry_count"]  = {int(k): v for k, v in raw.get("retry_count", {}).items()}
        raw["next_retry"]   = {int(k): v for k, v in raw.get("next_retry", {}).items()}
        return raw
    return {}


def save_dtn_state(state: dict):
    """Persist DTN state so aircraft can resume after restart."""
    out = {
        "session_id":   state["session_id"],
        "bundle_hash":  state["bundle_hash"],
        "total_chunks": state["total_chunks"],
        "acked_chunks": sorted(state["acked_chunks"]),
        "retry_count":  {str(k): v for k, v in state["retry_count"].items()},
        "next_retry":   {str(k): v for k, v in state["next_retry"].items()},
    }
    with open(cfg.DTN_STATE_FILE, "w") as f:
        json.dump(out, f)


# ── Build signed bundle ───────────────────────────────────────────────────────

def split_signed(data: bytes):
    """
    Parse a signed blob back into (bundle, sig).
    Layout: [compress_bundle bytes][2B sig_len][sig_bytes]
    Bundle size is determined by parsing the compress header — no guesswork.
    """
    from compress import BUNDLE_FMT, BUNDLE_HDR_SZ
    _, _, _, _, tele_comp_len, _, audio_comp_len, _ = struct.unpack_from(BUNDLE_FMT, data)
    bundle_end = BUNDLE_HDR_SZ + tele_comp_len + audio_comp_len
    sig_len    = struct.unpack_from("!H", data, bundle_end)[0]
    bundle     = data[:bundle_end]
    sig        = data[bundle_end + 2 : bundle_end + 2 + sig_len]
    return bundle, sig


def build_signed_bundle(session_id: bytes, private_key):
    tele_raw, _ = generate_telemetry()
    audio_raw   = generate_audio()

    bundle          = compress_bundle(session_id, tele_raw, audio_raw)
    payload_to_sign = bundle[BUNDLE_HDR_SZ:]   # compressed body only

    print("\n── Crypto comparison ─────────────────────────────────────────")
    bm = benchmark(payload_to_sign, n=3)
    print(f"  ECDSA P-256  sign: {bm['ecdsa_sign_ms']:.1f}ms  "
          f"verify: {bm['ecdsa_verify_ms']:.1f}ms  sig: {bm['ecdsa_sig_bytes']}B")
    print(f"  Lattice-LWE  sign: {bm['lattice_sign_ms']:.1f}ms  "
          f"verify: {bm['lattice_verify_ms']:.1f}ms  sig: {bm['lattice_sig_bytes']}B  "
          f"ok: {bm['lattice_verify_ok']}")
    print(f"  Lattice note: {bm['note']}")
    print("──────────────────────────────────────────────────────────────")

    ecdsa_sig = ecdsa_sign(private_key, payload_to_sign)
    # Layout: bundle + 2B_sig_len + sig_bytes
    signed    = bundle + struct.pack("!H", len(ecdsa_sig)) + ecdsa_sig

    import hashlib
    bundle_hash = hashlib.sha256(signed).hexdigest()
    print(f"\nSigned bundle: {len(signed):,}B  hash: {bundle_hash[:16]}...")
    return signed, bundle_hash


# ── Socket helpers ────────────────────────────────────────────────────────────

def open_sockets():
    """One TX socket, one RX socket for ACKs."""
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("0.0.0.0", cfg.ACK_PORT))
    rx.settimeout(0.1)
    return tx, rx


def drain_acks(rx, acked: set):
    """Pull all pending bitmap ACKs and expand into acked set."""
    newly = set()
    while True:
        try:
            data, addr = rx.recvfrom(256)
            win_start, bitmap = parse_ack(data)
            for bit in range(64):
                if bitmap & (1 << bit):
                    acked.add(win_start + bit)
                    newly.add(win_start + bit)
        except (socket.timeout, ValueError):
            break
    return newly


# ── Main send loop ────────────────────────────────────────────────────────────

def send_bundle(bundle: bytes, session_id: bytes, state: dict):
    """
    Send all chunks to all ground stations.
    Retransmit only un-ACKed chunks using exponential backoff.
    Persist state to disk each cycle.
    """
    raw_chunks = [bundle[i:i+cfg.CHUNK_SIZE]
                  for i in range(0, len(bundle), cfg.CHUNK_SIZE)]
    total      = len(raw_chunks)
    state["total_chunks"] = total

    # Precompute FEC parity packets
    fec_parities = {}   # grp_id → parity_bytes
    for grp_start in range(0, total, FEC_K):
        grp_end = min(grp_start + FEC_K, total)
        grp_id  = grp_start // FEC_K
        fec_parities[grp_id] = _xor_parity(raw_chunks[grp_start:grp_end])

    tx, rx = open_sockets()
    acked        = state["acked_chunks"]
    retry_count  = state["retry_count"]
    next_retry   = state["next_retry"]
    seq          = state.get("last_seq", 0)

    print(f"\n── Sending {total} chunks to {len(cfg.GROUND_STATIONS)} ground station(s) ──")
    print(f"   ACKed already: {len(acked)}/{total}  (from previous run)")

    def _send_chunk(idx, payload, flags=0, fec_grp=0):
        nonlocal seq
        seq += 1
        pkt = make_packet(session_id, seq, idx, total, payload, flags, fec_grp)
        for gs in cfg.GROUND_STATIONS:
            try:
                tx.sendto(pkt, (gs["host"], gs["port"]))
            except OSError:
                pass   # ground station offline; DTN will retry
        return seq

    try:
        while len(acked) < total:
            now = time.time()
            drain_acks(rx, acked)

            for idx in range(total):
                if idx in acked:
                    continue
                if now < next_retry.get(idx, 0):
                    continue
                rc = retry_count.get(idx, 0)
                if rc > cfg.DTN_MAX_RETRIES:
                    print(f"  [GIVE UP] chunk {idx} after {rc} retries")
                    acked.add(idx)   # stop retrying
                    continue

                grp_id   = idx // FEC_K
                flags    = FLAG_RETX if rc > 0 else 0
                last_seq = _send_chunk(idx, raw_chunks[idx], flags, grp_id)
                tag = "RETX" if rc > 0 else "SENT"
                print(f"  [{tag}] chunk {idx+1:>4}/{total}  "
                      f"seq={last_seq:<5}  retry={rc}  "
                      f"acked={len(acked)}/{total}")

                # Send FEC parity when we finish a group
                if (idx + 1) % FEC_K == 0 or idx == total - 1:
                    grp_start = grp_id * FEC_K
                    _send_chunk(grp_start, fec_parities[grp_id], FLAG_PARITY, grp_id)

                retry_count[idx] = rc + 1
                backoff = min(cfg.DTN_BASE_SEC * (2 ** rc), cfg.DTN_MAX_SEC)
                next_retry[idx]  = now + backoff

                # Slow send so you can kill ground station and watch DTN kick in
                time.sleep(0.5)

            state["last_seq"] = seq
            save_dtn_state(state)

            if len(acked) < total:
                still_missing = [i for i in range(total) if i not in acked]
                earliest_retry = min(next_retry.get(i, 0) for i in still_missing)
                wait = max(0, earliest_retry - time.time())
                if wait > 0:
                    print(f"  [DTN] all pending — waiting {wait:.1f}s before next retry...")
                    time.sleep(min(wait, 2.0))

    except KeyboardInterrupt:
        print("\nInterrupted — DTN state saved, resume by re-running aircraft.py")
    finally:
        tx.close()
        rx.close()


def _xor_parity(payloads: list) -> bytes:
    max_len = max(len(p) for p in payloads)
    result  = bytearray(max_len)
    for p in payloads:
        for i, b in enumerate(p):
            result[i] ^= b
    return bytes(result)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    private_key = ensure_keys()
    session_id  = uuid.uuid4().bytes

    state = load_dtn_state()
    if state:
        print(f"Resuming DTN session {state['session_id'][:16]}... "
              f"({len(state['acked_chunks'])} chunks already ACKed)")
        session_id = bytes.fromhex(state["session_id"])
        # Re-read bundle from disk if it exists
        bundle_path = "output/bundle_signed.bin"
        if os.path.exists(bundle_path):
            with open(bundle_path, "rb") as f:
                bundle = f.read()
        else:
            bundle, bh = build_signed_bundle(session_id, private_key)
            with open(bundle_path, "wb") as f:
                f.write(bundle)
    else:
        bundle, bundle_hash = build_signed_bundle(session_id, private_key)
        bundle_path = "output/bundle_signed.bin"
        with open(bundle_path, "wb") as f:
            f.write(bundle)
        state = {
            "session_id":   session_id.hex(),
            "bundle_hash":  bundle_hash,
            "total_chunks": 0,
            "acked_chunks": set(),
            "retry_count":  {},
            "next_retry":   {},
        }
        save_dtn_state(state)
        print(f"New session: {session_id.hex()[:16]}...")

    print(f"\nGround stations: {[gs['name'] for gs in cfg.GROUND_STATIONS]}")
    print(f"ACK listen port: {cfg.ACK_PORT}")
    send_bundle(bundle, session_id, state)

    print(f"\nSession complete. Chunks ACKed: {len(state['acked_chunks'])}/{state['total_chunks']}")
    # Clean up DTN state on successful completion
    if len(state["acked_chunks"]) >= state["total_chunks"]:
        os.remove(cfg.DTN_STATE_FILE)
        print("DTN state cleared (all chunks ACKed).")


if __name__ == "__main__":
    main()
