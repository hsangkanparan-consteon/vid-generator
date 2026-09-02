package keystore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"
)

var (
	ErrTenantKeyNotFound = errors.New("tenant key not found in keystore")
	ErrInvalidTenantID   = errors.New("tenant ID must be a 14-digit numeric string")
)

// TenantKeyRecord represents a tenant's cryptographic key pair stored at rest.
type TenantKeyRecord struct {
	TenantID           string    `json:"tenant_id"`             // 14-digit numeric string (e.g. "10002000300040", "00000000000000" for Global)
	KeyVersion         uint8     `json:"key_version"`           // Key Version identifier (e.g. 1)
	PublicKey          []byte    `json:"public_key"`            // 32-byte Ed25519 public key
	EncryptedPrivateKey []byte   `json:"encrypted_private_key"` // Ed25519 private key encrypted via Master KMS Key
	CreatedAt          time.Time `json:"created_at"`
}

// Keystore manages storage and retrieval of tenant cryptographic keys with envelope encryption.
type Keystore interface {
	GetTenantKey(ctx context.Context, tenantID string, keyVer uint8) (*TenantKeyRecord, error)
	SaveTenantKey(ctx context.Context, record *TenantKeyRecord) error
	GetDecryptedPrivateKey(ctx context.Context, tenantID string, keyVer uint8) (ed25519.PrivateKey, error)
	GenerateTenantKey(ctx context.Context, tenantID string, keyVer uint8) (*TenantKeyRecord, error)
}
