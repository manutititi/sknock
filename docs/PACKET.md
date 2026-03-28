# Sknock Packet Format

## Overview

**186 bytes, UDP, single datagram.**

Derived from Anchor SPA v2. The `wg_pubkey` field (VPN-specific) is repurposed
as the `rule` field (which action to trigger). Packet size and crypto are identical.

## Byte Layout

```
Offset  Size  Field          Description
──────────────────────────────────────────────────────────────────
  0     32    ephemeral_pub  Client's ephemeral X25519 public key (raw bytes)
 32     12    nonce          AES-GCM nonce (96-bit, NIST recommended)
 44    122    ciphertext     AES-256-GCM encrypted payload (see below)
166     16    tag            GCM authentication tag
182      4    version        Magic bytes: 0x00 0x02 0x00 0x00

Total: 186 bytes
```

## Encrypted Payload (122 bytes plaintext)

```
Offset  Size  Field      Description
────────────────────────────────────────────────────────────────
  0     64    uid        Username, UTF-8, null-padded to 64 bytes
 64      6    otp        TOTP code, ASCII digits, null-padded to 6 bytes
 70      8    timestamp  Unix epoch, uint64 big-endian
 78     44    rule       Rule name, ASCII, null-padded to 44 bytes

Total: 122 bytes
```

## Crypto Details

```
Algorithm:    ECIES with X25519 + AES-256-GCM + HKDF-SHA256

Key exchange:
  client generates ephemeral X25519 keypair (new per packet)
  shared_secret = X25519(eph_priv, server_pub)
  aes_key = HKDF-SHA256(shared_secret, salt="spa-v2", info="spa-v2-aes-key", length=32)

Encryption:
  nonce = crypto/rand (12 bytes)
  ciphertext || tag = AES-256-GCM(aes_key, nonce, payload, aad=nil)

Version marker: 0x00 0x02 0x00 0x00 (appended after tag, not encrypted)
```

## Security Properties

| Property | How |
|----------|-----|
| Confidentiality | AES-256-GCM — payload fully encrypted |
| Authentication | GCM tag — forged packets fail decryption |
| Perfect forward secrecy | Fresh ephemeral X25519 keypair per packet |
| Unlinkability | Each packet's ephemeral pub is random — two packets from same user look unrelated |
| Anti-replay | 12-byte nonce stored in sync.Map with 60s TTL |
| Freshness | Timestamp checked ±30s |
| Zero metadata | Observer sees only: 32B random key + 12B nonce + encrypted blob + version |

## What an Observer Sees

```
[random 32 bytes][random 12 bytes][random 122 bytes][random 16 bytes][0x00 0x02 0x00 0x00]
```

No IP, no username, no rule name, no identity of any kind is visible.
The version bytes (4 bytes) are the only non-random field.

## Version History

| Version bytes     | Size  | Notes |
|-------------------|-------|-------|
| (none)            | 154 B | Anchor SPA v1 — plaintext payload, TOTP only. Dropped. |
| 0x00 0x02 0x00 0x00 | 186 B | Anchor SPA v2 / Sknock v1 — ECIES, wg_pubkey→rule |

## Building a Packet (Go pseudocode)

```go
func BuildPacket(uid, otp, rule, serverPubKeyB64 string) ([]byte, error) {
    serverPub := decodeB64(serverPubKeyB64) // 32 bytes

    // Fresh ephemeral keypair
    ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
    ephPub := ephPriv.PublicKey().Bytes() // 32 bytes

    // ECDH
    serverKey, _ := ecdh.X25519().NewPublicKey(serverPub)
    shared, _ := ephPriv.ECDH(serverKey)

    // HKDF
    hkdf := hkdf.New(sha256.New, shared, []byte("spa-v2"), []byte("spa-v2-aes-key"))
    aesKey := make([]byte, 32)
    io.ReadFull(hkdf, aesKey)

    // Payload
    payload := make([]byte, 122)
    copy(payload[0:64],  padNull([]byte(uid),  64))
    copy(payload[64:70], padNull([]byte(otp),  6))
    binary.BigEndian.PutUint64(payload[70:78], uint64(time.Now().Unix()))
    copy(payload[78:122], padNull([]byte(rule), 44))

    // AES-256-GCM
    block, _ := aes.NewCipher(aesKey)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, 12)
    rand.Read(nonce)
    ctWithTag := gcm.Seal(nil, nonce, payload, nil) // 122+16 = 138 bytes

    // Assemble: eph_pub(32) + nonce(12) + ct(122) + tag(16) + version(4)
    pkt := concat(ephPub, nonce, ctWithTag[:122], ctWithTag[122:], []byte{0,2,0,0})
    return pkt, nil // 186 bytes
}
```

## Parsing a Packet (Go pseudocode)

```go
func ParsePacket(data []byte, serverPriv *ecdh.PrivateKey) (*SPAData, error) {
    if len(data) != 186 { return nil, ErrWrongSize }
    if !bytes.Equal(data[182:], []byte{0,2,0,0}) { return nil, ErrBadVersion }

    ephPub, _ := ecdh.X25519().NewPublicKey(data[0:32])
    nonce     := data[32:44]
    ct        := data[44:166]  // 122 bytes
    tag       := data[166:182] // 16 bytes

    shared, _ := serverPriv.ECDH(ephPub)
    // ... HKDF same as above ...
    // AES-GCM decrypt(ct || tag)
    payload, err := gcm.Open(nil, nonce, append(ct, tag...), nil)
    if err != nil { return nil, ErrDecryptFailed } // silent drop

    uid  := strings.TrimRight(string(payload[0:64]),  "\x00")
    otp  := strings.TrimRight(string(payload[64:70]), "\x00")
    ts   := binary.BigEndian.Uint64(payload[70:78])
    rule := strings.TrimRight(string(payload[78:122]), "\x00")

    if abs(time.Now().Unix() - int64(ts)) > 30 { return nil, ErrTimestamp }

    return &SPAData{UID: uid, OTP: otp, Timestamp: ts, Rule: rule}, nil
}
```
