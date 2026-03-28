package spa

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func generateTestKeypair(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func TestBuildParseRoundtrip(t *testing.T) {
	serverPriv := generateTestKeypair(t)
	serverPub := serverPriv.PublicKey().Bytes()

	uid := "alice"
	otp := "123456"
	rule := "open_ssh"

	pkt, err := BuildPacket(uid, otp, rule, serverPub)
	if err != nil {
		t.Fatalf("BuildPacket: %v", err)
	}

	if len(pkt) != PacketSize {
		t.Fatalf("packet size = %d, want %d", len(pkt), PacketSize)
	}

	data, err := ParsePacket(pkt, serverPriv)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}

	if data.UID != uid {
		t.Errorf("UID = %q, want %q", data.UID, uid)
	}
	if data.OTP != otp {
		t.Errorf("OTP = %q, want %q", data.OTP, otp)
	}
	if data.Rule != rule {
		t.Errorf("Rule = %q, want %q", data.Rule, rule)
	}
}

func TestWrongSize(t *testing.T) {
	serverPriv := generateTestKeypair(t)
	_, err := ParsePacket(make([]byte, 100), serverPriv)
	if err != ErrWrongSize {
		t.Errorf("expected ErrWrongSize, got %v", err)
	}
}

func TestBadVersion(t *testing.T) {
	serverPriv := generateTestKeypair(t)
	serverPub := serverPriv.PublicKey().Bytes()

	pkt, _ := BuildPacket("alice", "123456", "test", serverPub)
	// Corrupt version bytes
	pkt[184] = 0xFF

	_, err := ParsePacket(pkt, serverPriv)
	if err != ErrBadVersion {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}

func TestWrongKey(t *testing.T) {
	serverPriv := generateTestKeypair(t)
	wrongPriv := generateTestKeypair(t)
	serverPub := serverPriv.PublicKey().Bytes()

	pkt, _ := BuildPacket("alice", "123456", "test", serverPub)

	_, err := ParsePacket(pkt, wrongPriv)
	if err != ErrDecryptFailed {
		t.Errorf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestCorruptedCiphertext(t *testing.T) {
	serverPriv := generateTestKeypair(t)
	serverPub := serverPriv.PublicKey().Bytes()

	pkt, _ := BuildPacket("alice", "123456", "test", serverPub)
	// Corrupt ciphertext
	pkt[50] ^= 0xFF

	_, err := ParsePacket(pkt, serverPriv)
	if err != ErrDecryptFailed {
		t.Errorf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestNonceExtraction(t *testing.T) {
	serverPriv := generateTestKeypair(t)
	serverPub := serverPriv.PublicKey().Bytes()

	pkt, _ := BuildPacket("alice", "123456", "test", serverPub)

	nonce := Nonce(pkt)
	if len(nonce) != NonceSize {
		t.Fatalf("nonce len = %d, want %d", len(nonce), NonceSize)
	}
}
