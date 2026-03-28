package spa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	PacketSize  = 186
	EphPubSize  = 32
	NonceSize   = 12
	PayloadSize = 122
	TagSize     = 16
	VersionSize = 4

	UIDSize       = 64
	OTPSize       = 6
	TimestampSize = 8
	RuleSize      = 44

	TimestampWindow = 30 // seconds

	hkdfSalt = "spa-v2"
	hkdfInfo = "spa-v2-aes-key"
)

var VersionBytes = []byte{0x00, 0x02, 0x00, 0x00}

var (
	ErrWrongSize     = errors.New("packet size must be 186 bytes")
	ErrBadVersion    = errors.New("invalid version bytes")
	ErrDecryptFailed = errors.New("ECIES decryption failed")
	ErrTimestamp     = errors.New("timestamp outside allowed window")
)

type SPAData struct {
	UID       string
	OTP       string
	Timestamp uint64
	Rule      string
}

func deriveAESKey(sharedSecret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, []byte(hkdfSalt), []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

func padNull(data []byte, size int) []byte {
	out := make([]byte, size)
	copy(out, data)
	return out
}

// BuildPacket creates a 186-byte SPA v2 packet.
func BuildPacket(uid, otp, rule string, serverPubBytes []byte) ([]byte, error) {
	curve := ecdh.X25519()

	serverPub, err := curve.NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephPubBytes := ephPriv.PublicKey().Bytes()

	shared, err := ephPriv.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	aesKey, err := deriveAESKey(shared)
	if err != nil {
		return nil, err
	}

	// Build plaintext payload (122 bytes)
	payload := make([]byte, PayloadSize)
	copy(payload[0:UIDSize], padNull([]byte(uid), UIDSize))
	copy(payload[UIDSize:UIDSize+OTPSize], padNull([]byte(otp), OTPSize))
	binary.BigEndian.PutUint64(payload[UIDSize+OTPSize:UIDSize+OTPSize+TimestampSize], uint64(time.Now().Unix()))
	copy(payload[UIDSize+OTPSize+TimestampSize:], padNull([]byte(rule), RuleSize))

	// AES-256-GCM encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	ctWithTag := gcm.Seal(nil, nonce, payload, nil) // 122 + 16 = 138 bytes
	ct := ctWithTag[:PayloadSize]
	tag := ctWithTag[PayloadSize:]

	// Assemble: eph_pub(32) + nonce(12) + ct(122) + tag(16) + version(4) = 186
	pkt := make([]byte, 0, PacketSize)
	pkt = append(pkt, ephPubBytes...)
	pkt = append(pkt, nonce...)
	pkt = append(pkt, ct...)
	pkt = append(pkt, tag...)
	pkt = append(pkt, VersionBytes...)

	return pkt, nil
}

// ParsePacket decrypts and validates a 186-byte SPA v2 packet.
func ParsePacket(data []byte, serverPriv *ecdh.PrivateKey) (*SPAData, error) {
	if len(data) != PacketSize {
		return nil, ErrWrongSize
	}
	if !bytes.Equal(data[PacketSize-VersionSize:], VersionBytes) {
		return nil, ErrBadVersion
	}

	ephPubBytes := data[0:EphPubSize]
	nonce := data[EphPubSize : EphPubSize+NonceSize]
	ct := data[EphPubSize+NonceSize : EphPubSize+NonceSize+PayloadSize]
	tag := data[EphPubSize+NonceSize+PayloadSize : EphPubSize+NonceSize+PayloadSize+TagSize]

	curve := ecdh.X25519()
	ephPub, err := curve.NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	shared, err := serverPriv.ECDH(ephPub)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	aesKey, err := deriveAESKey(shared)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	// GCM Open expects ciphertext || tag
	ctAndTag := make([]byte, 0, len(ct)+len(tag))
	ctAndTag = append(ctAndTag, ct...)
	ctAndTag = append(ctAndTag, tag...)

	payload, err := gcm.Open(nil, nonce, ctAndTag, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	uid := strings.TrimRight(string(payload[0:UIDSize]), "\x00")
	otp := strings.TrimRight(string(payload[UIDSize:UIDSize+OTPSize]), "\x00")
	ts := binary.BigEndian.Uint64(payload[UIDSize+OTPSize : UIDSize+OTPSize+TimestampSize])
	rule := strings.TrimRight(string(payload[UIDSize+OTPSize+TimestampSize:]), "\x00")

	now := uint64(time.Now().Unix())
	var diff uint64
	if now > ts {
		diff = now - ts
	} else {
		diff = ts - now
	}
	if diff > TimestampWindow {
		return nil, ErrTimestamp
	}

	return &SPAData{
		UID:       uid,
		OTP:       otp,
		Timestamp: ts,
		Rule:      rule,
	}, nil
}

// Nonce returns the 12-byte nonce from a raw packet (for dedup).
func Nonce(data []byte) []byte {
	if len(data) < EphPubSize+NonceSize {
		return nil
	}
	return data[EphPubSize : EphPubSize+NonceSize]
}
