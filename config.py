"""Shared configuration — aircraft, ground stations, and protocol constants."""

import os

# ── Network ───────────────────────────────────────────────────────────────────
GROUND_STATIONS = [
    {"host": "127.0.0.1", "port": 9000, "name": "GS-Primary"},
    {"host": "127.0.0.1", "port": 9001, "name": "GS-Backup"},
]
ACK_PORT        = 9100   # aircraft listens here for ACKs from any ground station
CHUNK_SIZE      = 900    # bytes per packet payload

# ── Keys ─────────────────────────────────────────────────────────────────────
PRIVATE_KEY_PATH = "keys/aircraft_private.pem"
PUBLIC_KEY_PATH  = "keys/aircraft_public.pem"
HMAC_KEY         = b"fdr-hmac-shared-2024"

# ── DTN retransmit policy ─────────────────────────────────────────────────────
DTN_BASE_SEC     = 1.0   # first retry after 1s
DTN_MAX_SEC      = 30.0  # cap at 30s
DTN_MAX_RETRIES  = 10    # give up after 10 retries per chunk

# ── Store-and-forward state file (survives process restart) ──────────────────
DTN_STATE_FILE   = "output/dtn_state.json"

# ── Telemetry ─────────────────────────────────────────────────────────────────
DURATION_SEC     = 60
