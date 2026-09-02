package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestEd25519SigningAndVerification(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(priv))
	}

	message := []byte("https://autsorz/l/test-location-token-bytes")

	sig, err := Sign(priv, message)
	if err != nil {
		t.Fatalf("failed to sign message: %v", err)
	}

	if len(sig) != ed25519.SignatureSize {
		t.Errorf("expected signature size %d, got %d", ed25519.SignatureSize, len(sig))
	}

	// 1. Valid verification
	if !Verify(pub, message, sig) {
		t.Error("valid signature failed verification")
	}

	// 2. Tampered message rejection
	tamperedMessage := []byte("https://autsorz/l/test-location-token-byteX")
	if Verify(pub, tamperedMessage, sig) {
		t.Error("tampered message incorrectly verified")
	}

	// 3. Tampered signature rejection
	sig[0] ^= 0xFF
	if Verify(pub, message, sig) {
		t.Error("tampered signature incorrectly verified")
	}
}

func TestBase64URLCodec(t *testing.T) {
	data := []byte{0x00, 0xFF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	encoded := EncodeBase64URL(data)
	decoded, err := DecodeBase64URL(encoded)
	if err != nil {
		t.Fatalf("failed to decode Base64URL: %v", err)
	}

	if string(data) != string(decoded) {
		t.Errorf("Base64URL mismatch: got %x, expected %x", decoded, data)
	}
}
