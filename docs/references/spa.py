"""
SPA v2 (Single Packet Authorization) — ECIES packet builder / parser.
Reference implementation from Anchor project (server/code/vpn/spa.py).

Packet layout — 186 bytes total:
  [ 32 B  ephemeral_pub ]  client's ephemeral X25519 public key (raw bytes)
  [ 12 B  nonce         ]  AES-GCM nonce (96-bit, NIST standard)
  [122 B  ciphertext    ]  AES-256-GCM encrypted payload (same length as plaintext)
  [ 16 B  tag           ]  GCM authentication tag
  [  4 B  version       ]  0x00 0x02 0x00 0x00

Encrypted payload (122 bytes plaintext):
  [ 64 B  uid      ]  username, null-padded  ← ENCRYPTED, invisible to observer
  [  6 B  otp      ]  TOTP code — ASCII digits, null-padded
  [  8 B  timestamp]  Unix epoch — uint64 big-endian
  [ 44 B  wg_pubkey]  WireGuard public key — base64 ASCII, null-padded
                      ↑ In Sknock this field becomes: rule name (44B)

Crypto:
  ECIES: client generates ephemeral X25519 keypair, performs DH with server pubkey.
  Shared secret → HKDF-SHA256 (salt="spa-v2", info="spa-v2-aes-key") → 32-byte AES key.
  AES-256-GCM with 12-byte nonce, no AAD.

Zero plaintext metadata: an observer sees only an ephemeral public key (random,
unlinkable per packet), a nonce, ciphertext, a version tag. No username, no identity.

Anti-replay: the 12-byte nonce must be unique in the vpn_nonces TTL collection.
Timestamp also checked for ±30 s skew.

SPA v1 packets (154 bytes) are silently dropped — wrong size.
"""
import base64
import ipaddress
import logging
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Packet constants
# ---------------------------------------------------------------------------

EPHEMERAL_PUB_SIZE = 32   # X25519 public key (raw)
NONCE_SIZE = 12            # AES-GCM nonce (96-bit)
UID_SIZE = 64              # username, null-padded
OTP_SIZE = 6               # TOTP code (ASCII digits)
TS_SIZE = 8                # uint64 big-endian timestamp
PUBKEY_SIZE = 44           # WireGuard base64 public key (repurposed as rule in Sknock)
TAG_SIZE = 16              # GCM authentication tag
VERSION_SIZE = 4           # packet version marker
VERSION = b"\x00\x02\x00\x00"

PAYLOAD_SIZE = UID_SIZE + OTP_SIZE + TS_SIZE + PUBKEY_SIZE   # 122
PACKET_SIZE = EPHEMERAL_PUB_SIZE + NONCE_SIZE + PAYLOAD_SIZE + TAG_SIZE + VERSION_SIZE  # 186

# Maximum allowed clock skew (matches TOTP valid_window=1).
TIMESTAMP_WINDOW = 30

# Byte offsets within the packet
_OFF_NONCE = EPHEMERAL_PUB_SIZE                                           # 32
_OFF_CT    = EPHEMERAL_PUB_SIZE + NONCE_SIZE                              # 44
_OFF_TAG   = EPHEMERAL_PUB_SIZE + NONCE_SIZE + PAYLOAD_SIZE               # 166
_OFF_VER   = EPHEMERAL_PUB_SIZE + NONCE_SIZE + PAYLOAD_SIZE + TAG_SIZE    # 182


# ---------------------------------------------------------------------------
# Module-level server keypair (initialized once at startup)
# ---------------------------------------------------------------------------

_spa_privkey: Optional[X25519PrivateKey] = None
_spa_pubkey_b64: str = ""


def init_server_keypair(privkey_b64: str = "") -> str:
    """
    Initialize the SPA server X25519 keypair.

    If privkey_b64 is provided (SPA_PRIVKEY_B64 env var), load that key.
    Otherwise auto-generate, log the private key for copy-paste into .env,
    and use it for this process lifetime only.

    Returns the public key as base64 (safe to share, included in provision tokens).
    """
    global _spa_privkey, _spa_pubkey_b64

    if privkey_b64:
        raw = base64.b64decode(privkey_b64)
        _spa_privkey = X25519PrivateKey.from_private_bytes(raw)
        logger.info("SPA keypair loaded from SPA_PRIVKEY_B64.")
    else:
        _spa_privkey = X25519PrivateKey.generate()
        raw = _spa_privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        generated_b64 = base64.b64encode(raw).decode()
        logger.warning(
            "SPA_PRIVKEY_B64 not set — auto-generated for this session only.\n"
            "Add to your .env to make knock tokens persistent across restarts:\n"
            "  SPA_PRIVKEY_B64=%s",
            generated_b64,
        )

    pub_raw = _spa_privkey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _spa_pubkey_b64 = base64.b64encode(pub_raw).decode()
    logger.info("SPA public key: %s", _spa_pubkey_b64)
    return _spa_pubkey_b64


def get_spa_pubkey_b64() -> str:
    """Return the server SPA public key (base64). Empty if not initialized."""
    return _spa_pubkey_b64


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class SPAData:
    uid: str        # username (decrypted from payload)
    otp: str        # 6-digit TOTP code
    timestamp: int  # Unix epoch from packet
    wg_pubkey: str  # WireGuard public key (base64) — repurposed as rule name in Sknock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_aes_key(shared_secret: bytes) -> bytes:
    """HKDF-SHA256 over the X25519 shared secret → 32-byte AES key."""
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"spa-v2",
        info=b"spa-v2-aes-key",
    )
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def uid_to_ip(uid: int, subnet: str) -> str:
    """
    Deterministically compute the VPN IP for a given integer UID.
    UID=1 → subnet.1 (WireGuard server), UID=2 → subnet.2, etc.
    No database required — pure arithmetic.
    """
    net = ipaddress.IPv4Network(subnet, strict=False)
    return str(net.network_address + uid)


def build_packet(
    uid_str: str,
    otp_str: str,
    wg_pubkey: str,
    server_spa_pubkey_b64: str,
) -> bytes:
    """
    Build a 186-byte SPA v2 UDP packet ready to send to the knock listener.

    Args:
        uid_str:              Username.
        otp_str:              Current TOTP code (6 ASCII digits).
        wg_pubkey:            WireGuard public key (44-char base64 string).
                              In Sknock: rule name (44-char max, null-padded).
        server_spa_pubkey_b64: Server's SPA X25519 public key (base64).

    The uid is encrypted — an observer cannot determine who sent the packet.
    """
    # Load server public key
    server_pub_raw = base64.b64decode(server_spa_pubkey_b64)
    server_pub = X25519PublicKey.from_public_bytes(server_pub_raw)

    # Generate ephemeral X25519 keypair
    eph_priv = X25519PrivateKey.generate()
    eph_pub_raw = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # DH → shared secret → AES key
    shared = eph_priv.exchange(server_pub)
    aes_key = _derive_aes_key(shared)

    # Build plaintext payload (122 bytes)
    ts = int(time.time())
    payload = (
        uid_str.encode().ljust(UID_SIZE, b"\x00")[:UID_SIZE]
        + otp_str.encode().ljust(OTP_SIZE, b"\x00")[:OTP_SIZE]
        + struct.pack(">Q", ts)
        + wg_pubkey.encode().ljust(PUBKEY_SIZE, b"\x00")[:PUBKEY_SIZE]
    )

    # AES-256-GCM encrypt (returns ciphertext + 16-byte tag)
    nonce = os.urandom(NONCE_SIZE)
    ct_with_tag = AESGCM(aes_key).encrypt(nonce, payload, None)
    ciphertext = ct_with_tag[:PAYLOAD_SIZE]
    tag = ct_with_tag[PAYLOAD_SIZE:]

    return eph_pub_raw + nonce + ciphertext + tag + VERSION


def parse_packet(
    data: bytes,
    server_privkey: Optional[X25519PrivateKey] = None,
) -> Optional[SPAData]:
    """
    Parse and cryptographically validate an SPA v2 packet.

    Returns SPAData on success, None on any failure (silent drop semantics).
    Validates: exact packet size, version bytes, ECIES decryption, timestamp skew.
    Anti-replay (nonce uniqueness) must be enforced by the caller.

    Args:
        data:           Raw UDP payload (must be exactly PACKET_SIZE bytes).
        server_privkey: X25519 private key to use. Defaults to module-level
                        _spa_privkey (set by init_server_keypair at startup).
    """
    if len(data) != PACKET_SIZE:
        return None

    # Check version marker
    if data[_OFF_VER:] != VERSION:
        return None

    privkey = server_privkey or _spa_privkey
    if privkey is None:
        logger.error("SPA parse_packet: server keypair not initialized")
        return None

    eph_pub_raw = data[:EPHEMERAL_PUB_SIZE]
    nonce = data[_OFF_NONCE:_OFF_CT]
    ciphertext = data[_OFF_CT:_OFF_TAG]
    tag = data[_OFF_TAG:_OFF_VER]

    # ECIES: server DH with ephemeral client pubkey → shared secret → AES key
    try:
        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)
        shared = privkey.exchange(eph_pub)
        aes_key = _derive_aes_key(shared)
        payload = AESGCM(aes_key).decrypt(nonce, ciphertext + tag, None)
    except Exception:
        return None  # authentication failure or malformed key — silent drop

    # Extract fields from plaintext payload
    uid_str = payload[:UID_SIZE].rstrip(b"\x00").decode(errors="replace")
    otp_str = payload[UID_SIZE:UID_SIZE + OTP_SIZE].rstrip(b"\x00").decode(errors="replace")
    ts = struct.unpack(">Q", payload[UID_SIZE + OTP_SIZE:UID_SIZE + OTP_SIZE + TS_SIZE])[0]
    wg_pubkey = (
        payload[UID_SIZE + OTP_SIZE + TS_SIZE:]
        .rstrip(b"\x00")
        .decode(errors="replace")
    )

    if abs(int(time.time()) - ts) > TIMESTAMP_WINDOW:
        return None

    return SPAData(uid=uid_str, otp=otp_str, timestamp=ts, wg_pubkey=wg_pubkey)
