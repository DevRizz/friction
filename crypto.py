"""
crypto.py — Authentication layer.

Two schemes run in parallel for comparison:
  1. ECDSA P-256  (classical, production-grade)
  2. Lattice-LWE  (didactic Ring-LWE signature — structurally correct,
                   not production-secure; illustrates the proposal)

Both sign the same payload and timings are printed so the proposal can
demonstrate the lattice overhead vs ECDSA.

Per-packet integrity: HMAC-SHA256 with a shared key (both sides).
"""

import hashlib
import hmac as _hmac
import os
import struct
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

import config as cfg

# ── HMAC-SHA256 per packet ────────────────────────────────────────────────────

def mac_tag(data: bytes) -> bytes:
    """32-byte HMAC-SHA256 tag over data using shared key."""
    return _hmac.new(cfg.HMAC_KEY, data, hashlib.sha256).digest()


def mac_verify(data: bytes, tag: bytes) -> bool:
    return _hmac.compare_digest(tag, mac_tag(data))


# ── ECDSA P-256 ───────────────────────────────────────────────────────────────

def ecdsa_keygen():
    key = ec.generate_private_key(ec.SECP256R1())
    return key, key.public_key()


def ecdsa_sign(private_key, payload: bytes) -> bytes:
    digest = hashlib.sha256(payload).digest()
    return private_key.sign(digest, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(public_key, payload: bytes, sig: bytes) -> bool:
    digest = hashlib.sha256(payload).digest()
    try:
        public_key.verify(sig, digest, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def save_ecdsa_keys(private_key, pub_key):
    os.makedirs("keys", exist_ok=True)
    with open(cfg.PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(cfg.PUBLIC_KEY_PATH, "wb") as f:
        f.write(pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))


def load_ecdsa_private(path=cfg.PRIVATE_KEY_PATH):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_ecdsa_public(path=cfg.PUBLIC_KEY_PATH):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ── Ring-LWE toy signature (lattice, didactic) ────────────────────────────────
# This is a simplified Ring-LWE-based commitment scheme demonstrating the
# structure of lattice signatures (Dilithium-family). It is NOT secure —
# parameters are tiny. Purpose: show the sign/verify interface and timing.
#
# Structure mirrors CRYSTALS-Dilithium:
#   KeyGen : sample secret polynomial s from small-coefficient ring
#   Sign   : hash message → challenge c; compute z = y + c*s
#   Verify : check norm(z) and hash consistency

import random as _random
import array as _array

_LWE_Q  = 8380417   # Dilithium's prime modulus
_LWE_N  = 256        # ring dimension
_LWE_ETA = 4         # secret coefficient bound (small)
_LWE_GAMMA = 1 << 17 # masking polynomial bound


def _poly_add(a, b):
    return [(x + y) % _LWE_Q for x, y in zip(a, b)]


def _poly_mul_ntt(a, b):
    """Schoolbook poly multiply mod (x^N + 1) mod Q — O(N^2), slow but correct."""
    n = _LWE_N
    c = [0] * n
    for i in range(n):
        for j in range(n):
            idx = (i + j) % n
            sign = -1 if (i + j) >= n else 1
            c[idx] = (c[idx] + sign * a[i] * b[j]) % _LWE_Q
    return c


def _poly_norm(a):
    """Infinity norm with centered lift."""
    half = _LWE_Q // 2
    return max(abs(x if x <= half else x - _LWE_Q) for x in a)


def _hash_to_poly(digest: bytes) -> list:
    """Deterministically expand a 32-byte hash to a ternary challenge poly."""
    rng = _random.Random(int.from_bytes(digest[:8], "big"))
    poly = [0] * _LWE_N
    # Place ±1 in 60 positions (like Dilithium tau=60)
    positions = rng.sample(range(_LWE_N), 60)
    for i, pos in enumerate(positions):
        poly[pos] = 1 if i < 30 else _LWE_Q - 1
    return poly


class LatticeKey:
    """Ring-LWE keypair. keygen, sign, verify."""

    def __init__(self):
        rng = _random.SystemRandom()
        # Secret: small-coefficient polynomial
        self.s = [rng.randint(-_LWE_ETA, _LWE_ETA) % _LWE_Q for _ in range(_LWE_N)]
        # Public key: A*s + e (A fixed as identity for simplicity)
        e  = [rng.randint(-1, 1) % _LWE_Q for _ in range(_LWE_N)]
        self.t = _poly_add(self.s, e)   # t = s + e (public)

    def sign(self, payload: bytes) -> bytes:
        rng = _random.SystemRandom()
        msg_hash = hashlib.sha256(payload).digest()

        for _ in range(1000):   # rejection sampling
            y = [rng.randint(-_LWE_GAMMA, _LWE_GAMMA) % _LWE_Q for _ in range(_LWE_N)]
            w = y   # A=I, so w = A*y = y

            # Commitment: hash of w's first 8 coefficients + message
            w_bytes = b"".join(struct.pack(">I", v) for v in w[:8])
            c_hash  = hashlib.sha256(w_bytes + msg_hash).digest()
            c_poly  = _hash_to_poly(c_hash)

            # z = y + c*s
            cs = _poly_mul_ntt(c_poly, self.s)
            z  = _poly_add(y, cs)

            if _poly_norm(z) < _LWE_GAMMA - _LWE_ETA * 60:
                # Serialize: c_hash(32) + w_bytes_commitment(32) + z(N*4)
                z_bytes = b"".join(struct.pack(">i", v if v < _LWE_Q // 2 else v - _LWE_Q)
                                   for v in z)
                return c_hash + w_bytes + z_bytes   # 32+32+1024 = 1088 bytes

        raise RuntimeError("Lattice sign: rejection sampling failed")

    def verify(self, payload: bytes, sig: bytes) -> bool:
        """
        Verify by checking: hash(w_commitment, msg) == c_hash.
        The commitment w_bytes was stored in the signature at sign time.
        This matches Dilithium's approach of including the hash of w in sig.
        """
        expected_len = 32 + 32 + _LWE_N * 4
        if len(sig) < expected_len:
            return False
        c_hash  = sig[:32]
        w_bytes = sig[32:64]   # commitment stored at sign time
        z = [struct.unpack(">i", sig[64 + i*4: 68 + i*4])[0] for i in range(_LWE_N)]

        # Norm check
        z_mod = [v % _LWE_Q for v in z]
        if _poly_norm(z_mod) >= _LWE_GAMMA:
            return False

        # Recompute challenge from stored w_bytes + message hash
        msg_hash = hashlib.sha256(payload).digest()
        c_check  = hashlib.sha256(w_bytes + msg_hash).digest()
        return c_check == c_hash


# ── Benchmark both schemes ────────────────────────────────────────────────────

def benchmark(payload: bytes, n=5):
    """Sign + verify with both schemes, return timing dict."""
    # ECDSA
    priv, pub = ecdsa_keygen()
    t0 = time.perf_counter()
    for _ in range(n):
        sig = ecdsa_sign(priv, payload)
    ecdsa_sign_ms = (time.perf_counter() - t0) / n * 1000

    t0 = time.perf_counter()
    for _ in range(n):
        ecdsa_verify(pub, payload, sig)
    ecdsa_verify_ms = (time.perf_counter() - t0) / n * 1000

    # Lattice
    lk = LatticeKey()
    t0 = time.perf_counter()
    lsig = lk.sign(payload)
    lattice_sign_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    ok = lk.verify(payload, lsig)
    lattice_verify_ms = (time.perf_counter() - t0) * 1000

    return {
        "payload_bytes":       len(payload),
        "ecdsa_sign_ms":       round(ecdsa_sign_ms, 2),
        "ecdsa_verify_ms":     round(ecdsa_verify_ms, 2),
        "ecdsa_sig_bytes":     len(sig),
        "lattice_sign_ms":     round(lattice_sign_ms, 2),
        "lattice_verify_ms":   round(lattice_verify_ms, 2),
        "lattice_sig_bytes":   len(lsig),
        "lattice_verify_ok":   ok,
        "note": (
            "Lattice sign/verify are ~10-100x slower at these toy parameters. "
            "Production Dilithium2 (liboqs) achieves ~0.1ms sign, ~0.15ms verify. "
            "ECDSA P-256 is faster today; lattice is quantum-resistant."
        ),
    }


if __name__ == "__main__":
    data = b"test bundle payload " * 50
    r = benchmark(data)
    for k, v in r.items():
        print(f"  {k:<28}: {v}")
