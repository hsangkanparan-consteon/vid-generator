package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// MockKMSClient implements KMSClient using an in-memory AES-256-GCM key for local dev and tests.
type MockKMSClient struct {
	gcm     cipher.AEAD
	keyName string
}

// NewMockKMSClient creates a mock KMS client with a randomly generated 256-bit AES key.
func NewMockKMSClient() (*MockKMSClient, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &MockKMSClient{
		gcm:     gcm,
		keyName: "projects/local-dev/locations/global/keyRings/mock-ring/cryptoKeys/master-key",
	}, nil
}

func (m *MockKMSClient) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, m.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := m.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (m *MockKMSClient) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	nonceSize := m.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := m.gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("mock decryption failed: %w", err)
	}

	return plaintext, nil
}

func (m *MockKMSClient) KeyName() string {
	return m.keyName
}
