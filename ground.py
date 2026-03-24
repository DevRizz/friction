#!/usr/bin/env python3
"""
ground.py — Ground station receiver.

  - Listens on UDP port (configurable via --port)
  - Verifies HMAC-SHA256 per packet
  - Sends bitmap ACK per window (64-bit mask, covers 64 chunks per ACK)
  - Applies XOR-FEC recovery for single-erasure groups before requesting retransmit
  - On session complete: verify ECDSA signature, decompress, save output,
    compare received data vs re-generated original byte-for-byte
  - Multiple instances can run simultaneously (GS-Primary on 9000, GS-Backup on 9001)

Run as:
  python3 ground.py --port 9000 --name GS-Primary
  python3 ground.py --port 9001 --name GS-Backup
"""

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import time
import wave

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config as cfg
from crypto   import ecdsa_verify, load_ecdsa_public
from compress import decompress_bundle, BUNDLE_HDR_SZ
from protocol import (parse_packet, make_ack, fec_recover,
                       FLAG_PARITY, FLAG_RETX, FEC_K, ACK_FMT)

os.makedirs("output/received", exist_ok=True)


# ── Bitmap ACK emission ───────────────────────────────────────────────────────

def emit_bitmap_acks(sock, aircraft_port: int, received: set, total: int):
    """
    Send one ACK per 64-chunk window covering all received chunks.
    Ground sends these proactively so aircraft can retransmit only the gaps.
    """
    for win_start in range(0, total, 64):
        bitmap = 0
        for bit in range(64):
            if (win_start + bit) in received:
                bitmap |= (1 << bit)
        ack = make_ack(win_start, bitmap)
        try:
            sock.sendto(ack, ("127.0.0.1", aircraft_port))
        except OSError:
            pass


# ── FEC: attempt single-erasure recovery within each group ───────────────────

def try_fec_recovery(data_chunks: dict, fec_parities: dict, total: int, received: set):
    """
    For each FEC group that is exactly one chunk short, recover it from parity.
    Modifies data_chunks and received in place.
    """
    for grp_id, parity in list(fec_parities.items()):
        grp_start = grp_id * FEC_K
        grp_end   = min(grp_start + FEC_K, total)
        grp_idx   = list(range(grp_start, grp_end))
        present   = {i - grp_start: data_chunks[i] for i in grp_idx if i in data_chunks}
        missing   = [i for i in grp_idx if i not in data_chunks]
        if len(missing) == 1:
            try:
                recovered = fec_recover(present, len(grp_idx), parity)
                idx = missing[0]
                data_chunks[idx] = recovered
                received.add(idx)
                print(f"  [FEC] recovered chunk {idx} from group {grp_id} parity")
            except ValueError:
                pass


# ── Session finalization ──────────────────────────────────────────────────────

def split_signed(data: bytes):
    """Parse (bundle, sig) from signed blob. See aircraft.py for layout."""
    from compress import BUNDLE_FMT, BUNDLE_HDR_SZ
    _, _, _, _, tele_comp_len, _, audio_comp_len, _ = struct.unpack_from(BUNDLE_FMT, data)
    bundle_end = BUNDLE_HDR_SZ + tele_comp_len + audio_comp_len
    sig_len    = struct.unpack_from("!H", data, bundle_end)[0]
    bundle     = data[:bundle_end]
    sig        = data[bundle_end + 2 : bundle_end + 2 + sig_len]
    return bundle, sig


def finalize_session(session_hex: str, data_chunks: dict, total: int,
                     pkt_log: list, gs_name: str):
    """Reassemble, verify ECDSA, decompress, save, compare vs original."""
    bundle = b"".join(data_chunks[i] for i in range(total))
    sid8   = session_hex[:8]

    print(f"\n  Reassembled {len(bundle):,}B")

    try:
        bundle_body, sig = split_signed(bundle)
    except Exception as e:
        print(f"  ERROR parsing signed bundle: {e}")
        return

    payload_signed = bundle_body[BUNDLE_HDR_SZ:]

    # Load public key
    try:
        pub_key = load_ecdsa_public()
    except FileNotFoundError:
        print("  ERROR: keys/aircraft_public.pem not found — copy from aircraft machine")
        return

    ecdsa_ok = ecdsa_verify(pub_key, payload_signed, sig)
    print(f"  ECDSA signature : {'✓ VALID' if ecdsa_ok else '✗ INVALID'}")
    if not ecdsa_ok:
        print("  Aborting — signature invalid, data may be tampered")
        return

    # Decompress
    try:
        result = decompress_bundle(bundle_body)
    except Exception as e:
        print(f"  Decompress failed: {e}")
        return

    tele  = result["tele"]
    audio = result["audio"]
    algo  = result["algo"]
    print(f"  Algorithm       : {algo.upper()}")
    print(f"  Telemetry       : {result['tele_comp_len']:,}B → {result['tele_raw_len']:,}B")
    print(f"  Audio           : {result['audio_comp_len']:,}B → {result['audio_raw_len']:,}B")

    # Save files
    tele_path  = f"output/received/telemetry_{sid8}.bin"
    audio_path = f"output/received/audio_{sid8}.wav"
    with open(tele_path, "wb") as f:
        f.write(tele)
    with wave.open(audio_path, "wb") as wf:
        wf.setnchannels(1); wf.setsampwidth(1); wf.setframerate(8000)
        wf.writeframes(audio)
    print(f"  Saved telemetry : {tele_path}")
    print(f"  Saved audio     : {audio_path}")

    # ── Compare vs re-generated original ─────────────────────────────────────
    tele_match  = False
    audio_match = False
    if os.path.exists("output/telemetry_raw.bin"):
        orig_tele = open("output/telemetry_raw.bin", "rb").read()
        tele_match = (tele == orig_tele)
        print(f"  Tele match orig : {'MATCH ✓' if tele_match else 'MISMATCH ✗'} "
              f"({len(tele):,}B vs {len(orig_tele):,}B)")
    if os.path.exists("output/cvr_audio.wav"):
        with wave.open("output/cvr_audio.wav", "rb") as wf:
            orig_audio = wf.readframes(wf.getnframes())
        audio_match = (audio == orig_audio)
        print(f"  Audio match orig: {'MATCH ✓' if audio_match else 'MISMATCH ✗'} "
              f"({len(audio):,}B vs {len(orig_audio):,}B)")

    # ── Save receipt log ──────────────────────────────────────────────────────
    lats = [p["latency_ms"] for p in pkt_log if p.get("latency_ms") is not None]
    log  = {
        "gs_name":          gs_name,
        "session_id":       session_hex,
        "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_chunks":     total,
        "received_chunks":  len(data_chunks),
        "ecdsa_valid":      ecdsa_ok,
        "tele_match_orig":  tele_match,
        "audio_match_orig": audio_match,
        "algo":             algo,
        "tele_raw_bytes":   result["tele_raw_len"],
        "audio_raw_bytes":  result["audio_raw_len"],
        "avg_latency_ms":   round(sum(lats) / len(lats), 1) if lats else None,
        "p95_latency_ms":   sorted(lats)[int(len(lats) * 0.95)] if len(lats) > 1 else None,
        "packets":          pkt_log,
    }
    log_path = f"output/received/log_{sid8}_{gs_name}.json"
    with open(log_path, "w") as f:
        json.dump(log, f, indent=2)
    print(f"  Log             : {log_path}")


# ── Main receive loop ─────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Ground station receiver")
    ap.add_argument("--port",   type=int, default=9000)
    ap.add_argument("--name",   default="GS-Primary")
    ap.add_argument("--ack-port", type=int, default=cfg.ACK_PORT)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(1.0)

    print(f"{'='*55}")
    print(f"  {args.name}  —  listening on UDP :{args.port}")
    print(f"  ACK → aircraft :{args.ack_port}")
    print(f"  Auth: HMAC-SHA256 per pkt + ECDSA P-256 on bundle")
    print(f"  FEC: XOR parity, {FEC_K} data + 1 parity per group")
    print(f"{'='*55}\n")

    # Per-session state
    data_chunks  = {}   # chunk_idx → payload
    fec_parities = {}   # grp_id → parity bytes
    received     = set()
    pkt_log      = []
    total        = None
    session_hex  = None
    hmac_fails   = 0
    last_ack_t   = 0

    try:
        while True:
            try:
                data, sender = sock.recvfrom(65535)
            except socket.timeout:
                # Periodic bitmap ACK even during silence
                if total and time.time() - last_ack_t > 1.0:
                    emit_bitmap_acks(sock, args.ack_port, received, total)
                    last_ack_t = time.time()
                continue

            recv_t = time.time()

            try:
                fields, payload = parse_packet(data)
            except ValueError as e:
                hmac_fails += 1
                print(f"  [REJECT] {sender[0]}: {e}")
                continue

            sid_hex = fields["session"].hex()
            chunk   = fields["chunk"]
            tot     = fields["total"]
            flags   = fields["flags"]
            grp_id  = fields["fec_grp"]
            lat_ms  = round((recv_t - fields["ts_ms"] / 1000.0) * 1000, 1)

            if session_hex is None:
                session_hex = sid_hex
                total       = tot
                print(f"  [NEW] session {sid_hex[:16]}  total={tot}  from {sender[0]}")

            if flags & FLAG_PARITY:
                fec_parities[grp_id] = payload
                # Attempt recovery immediately if a group is one short
                try_fec_recovery(data_chunks, fec_parities, total, received)
            else:
                is_dup = chunk in received
                if not is_dup:
                    data_chunks[chunk] = payload
                    received.add(chunk)

                pkt_log.append({
                    "chunk": chunk, "seq": fields["seq"],
                    "ts_ms": fields["ts_ms"], "recv_t": round(recv_t, 4),
                    "latency_ms": lat_ms, "wire_bytes": fields["wire_bytes"],
                    "retx": bool(flags & FLAG_RETX), "dup": is_dup,
                    "from": sender[0],
                })
                tag = "DUP " if is_dup else "RECV"
                print(f"  [{tag}] chunk {chunk+1:>4}/{total}  "
                      f"seq={fields['seq']:<5}  "
                      f"lat={lat_ms}ms  "
                      f"got={len(received)}/{total}")

            # Send bitmap ACK every chunk (and after FEC recovery)
            emit_bitmap_acks(sock, args.ack_port, received, total)
            last_ack_t = time.time()

            # Check completion
            if total and len(received) >= total:
                print(f"\n  {'─'*48}")
                print(f"  All {total} chunks received (incl. FEC recovered).")
                finalize_session(session_hex, data_chunks, total, pkt_log, args.name)
                print(f"  {'─'*48}\n")
                # Reset for next session
                data_chunks  = {}
                fec_parities = {}
                received     = set()
                pkt_log      = []
                total        = None
                session_hex  = None

    except KeyboardInterrupt:
        print(f"\n{args.name} stopped.  HMAC failures: {hmac_fails}")
        partial_log = f"output/received/partial_{args.name}.json"
        if pkt_log:
            with open(partial_log, "w") as f:
                json.dump(pkt_log, f, indent=2)
            print(f"  Partial log saved: {partial_log}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
