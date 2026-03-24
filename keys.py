#!/usr/bin/env python3
"""
keys.py — Run once on aircraft machine to generate ECDSA keypair.
Copy keys/aircraft_public.pem to every ground station's keys/ folder.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto import ecdsa_keygen, save_ecdsa_keys
import config as cfg

os.makedirs("keys", exist_ok=True)

if os.path.exists(cfg.PRIVATE_KEY_PATH) and os.path.exists(cfg.PUBLIC_KEY_PATH):
    print(f"Keys already exist:\n  {cfg.PRIVATE_KEY_PATH}\n  {cfg.PUBLIC_KEY_PATH}")
    print("Delete them first to regenerate.")
else:
    priv, pub = ecdsa_keygen()
    save_ecdsa_keys(priv, pub)
    print(f"  Private key : {cfg.PRIVATE_KEY_PATH}  ← keep on aircraft ONLY")
    print(f"  Public key  : {cfg.PUBLIC_KEY_PATH}  ← copy to ground station(s)")

print("\nNext:")
print("  1. Copy keys/aircraft_public.pem → ground machine keys/")
print("  2. python3 ground.py --port 9000 --name GS-Primary")
print("  3. python3 ground.py --port 9001 --name GS-Backup")
print("  4. python3 aircraft.py")
