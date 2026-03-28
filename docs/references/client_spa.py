"""
SPA client — packet builder used by the CLI to send a knock.
Extracted from Anchor project (anchor/commands/vpn.py: _build_spa_packet and helpers).

In Sknock (Go):
  This becomes the 'sknock knock' subcommand.
  Uses the same ECIES/X25519 + AES-256-GCM logic.
  The wg_pubkey field is repurposed as the rule name (44 bytes, null-padded).
  Client reads seed from ~/.config/sknock/config.toml [server.<name>] section.
  Generates TOTP code locally from seed, builds packet, sends UDP datagram.
  Retries 3x with 200ms gap (idempotent — server deduplicates by nonce).

Go dependencies for this module:
  golang.org/x/crypto/curve25519    (or crypto/ecdh in Go 1.20+)
  crypto/aes + crypto/cipher        (AES-GCM, stdlib)
  golang.org/x/crypto/hkdf          (HKDF, or implement inline)
  github.com/pquerna/otp/totp       (TOTP code generation)
  encoding/binary                   (struct.pack equivalent)
  net                               (UDP socket)
"""
from __future__ import annotations

import base64
import os
import socket
import struct
import time
from typing import Optional


def build_spa_packet(
    uid_str: str,
    otp_str: str,
    rule_name: str,
    server_spa_pubkey_b64: str,
) -> bytes:
    """
    Build a 186-byte SPA v2 UDP packet (ECIES).

    Args:
        uid_str:               Username (max 64 chars).
        otp_str:               Current TOTP code (6 ASCII digits).
        rule_name:             Rule to trigger on the server (max 44 chars).
                               Replaces wg_pubkey field from original Anchor SPA.
        server_spa_pubkey_b64: Server's SPA X25519 public key (base64, 32 bytes).

    Returns 186 bytes ready to send as a UDP datagram.
    The uid is encrypted — an observer sees only random bytes.
    Each packet uses a fresh ephemeral keypair → unlinkable, forward secret.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

    UID_SIZE, OTP_SIZE, TS_SIZE, RULE_SIZE = 64, 6, 8, 44
    PAYLOAD_SIZE = UID_SIZE + OTP_SIZE + TS_SIZE + RULE_SIZE  # 122
    VERSION = b"\x00\x02\x00\x00"

    # Load server public key and generate ephemeral client keypair
    server_pub = X25519PublicKey.from_public_bytes(base64.b64decode(server_spa_pubkey_b64))
    eph_priv = X25519PrivateKey.generate()
    eph_pub_raw = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # DH → HKDF → AES key
    shared = eph_priv.exchange(server_pub)
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=b"spa-v2", info=b"spa-v2-aes-key")
    aes_key = hkdf.derive(shared)

    # Build plaintext payload: uid(64) + otp(6) + timestamp(8) + rule(44)
    ts = int(time.time())
    payload = (
        uid_str.encode().ljust(UID_SIZE, b"\x00")[:UID_SIZE]
        + otp_str.encode().ljust(OTP_SIZE, b"\x00")[:OTP_SIZE]
        + struct.pack(">Q", ts)
        + rule_name.encode().ljust(RULE_SIZE, b"\x00")[:RULE_SIZE]
    )

    # AES-256-GCM encrypt (returns ciphertext + 16-byte tag appended)
    nonce = os.urandom(12)
    ct_with_tag = AESGCM(aes_key).encrypt(nonce, payload, None)
    ciphertext = ct_with_tag[:PAYLOAD_SIZE]
    tag = ct_with_tag[PAYLOAD_SIZE:]

    # [ eph_pub(32) | nonce(12) | ciphertext(122) | tag(16) | version(4) ] = 186
    return eph_pub_raw + nonce + ciphertext + tag + VERSION


def send_knock(
    host: str,
    port: int,
    uid: str,
    seed: str,
    rule: str,
    server_pubkey_b64: str,
    retries: int = 3,
    retry_delay_ms: int = 200,
) -> None:
    """
    Send an SPA knock to host:port, retrying up to `retries` times.

    Retries are safe: the server deduplicates by nonce, so extra packets are
    ignored. The 30s TOTP window makes retries valid without regenerating OTP.

    Args:
        host:              Destination hostname or IP.
        port:              UDP port (default Sknock port: 58432).
        uid:               Username registered on the server.
        seed:              TOTP seed (base32) from local config.
        rule:              Rule name to trigger (e.g. "open_ssh").
        server_pubkey_b64: Server's X25519 SPA public key (base64).
        retries:           Number of UDP sends (default 3).
        retry_delay_ms:    Milliseconds between retries (default 200).
    """
    import pyotp
    otp = pyotp.TOTP(seed).now()
    packet = build_spa_packet(uid, otp, rule, server_pubkey_b64)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for i in range(retries):
            sock.sendto(packet, (host, port))
            if i < retries - 1:
                time.sleep(retry_delay_ms / 1000.0)
    finally:
        sock.close()
