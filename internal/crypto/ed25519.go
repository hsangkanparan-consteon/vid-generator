package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

var (
	ErrInvalidSignatureLength = errors.New("signature must be exactly 64 bytes")
	ErrInvalidPublicKeyLength = errors.New("public key must be exactly 32 bytes")
	ErrInvalidPrivateKeyLength = errors.New("private key must be exactly 64 bytes")
	ErrVerificationFailed     = errors.New("cryptographic signature verification failed (tampered or counterfeit token)")
)

// GenerateKeyPair generates a new cryptographically secure Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// Sign signs a message using an Ed25519 private key, returning a 64-byte signature.
func Sign(priv ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKeyLength
	}
	return ed25519.Sign(priv, message), nil
}

// Verify verifies an Ed25519 signature over a message against a 32-byte public key.
func Verify(pub ed25519.PublicKey, message, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message, signature)
}
