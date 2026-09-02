package keystore

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"sync"
	"time"

	"consteon.com/qr-generator/internal/crypto"
	"consteon.com/qr-generator/internal/kms"
)

// EncryptedKeystore implements Keystore using KMS envelope encryption and in-memory caching.
type EncryptedKeystore struct {
	kmsClient       kms.KMSClient
	firestoreSyncer *FirestoreSyncer
	mu              sync.RWMutex
	records         map[string]*TenantKeyRecord   // key: "tenantID:keyVer"
	keyCache        map[string]ed25519.PrivateKey // key: "tenantID:keyVer" (decrypted in-memory cache)
}

// SetFirestoreSyncer configures an optional real-time Firestore syncer for public keys.
func (k *EncryptedKeystore) SetFirestoreSyncer(syncer *FirestoreSyncer) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.firestoreSyncer = syncer
}

// NewEncryptedKeystore creates an EncryptedKeystore backed by a KMSClient.
func NewEncryptedKeystore(kmsClient kms.KMSClient) *EncryptedKeystore {
	return &EncryptedKeystore{
		kmsClient: kmsClient,
		records:   make(map[string]*TenantKeyRecord),
		keyCache:  make(map[string]ed25519.PrivateKey),
	}
}

func makeKey(tenantID string, keyVer uint8) string {
	return fmt.Sprintf("%s:%d", tenantID, keyVer)
}

// GetTenantKey returns the encrypted key record for a given tenant and version.
func (k *EncryptedKeystore) GetTenantKey(ctx context.Context, tenantID string, keyVer uint8) (*TenantKeyRecord, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	lookup := makeKey(tenantID, keyVer)
	rec, exists := k.records[lookup]
	if !exists {
		return nil, fmt.Errorf("%w: %s (version %d)", ErrTenantKeyNotFound, tenantID, keyVer)
	}
	return rec, nil
}

// SaveTenantKey stores a tenant key record in the keystore.
func (k *EncryptedKeystore) SaveTenantKey(ctx context.Context, record *TenantKeyRecord) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	lookup := makeKey(record.TenantID, record.KeyVersion)
	k.records[lookup] = record

	// Auto-sync public key in standard Base64 to Cloud Firestore for mobile apps
	if k.firestoreSyncer != nil {
		if err := k.firestoreSyncer.SyncPublicKey(ctx, record.TenantID, record.KeyVersion, record.PublicKey); err != nil {
			log.Printf("[WARN] Failed to auto-sync public key to Firestore for tenant %s v%d: %v", record.TenantID, record.KeyVersion, err)
		}
	}

	return nil
}

// GetDecryptedPrivateKey retrieves the Ed25519 private key, decrypting it via KMS if not cached.
func (k *EncryptedKeystore) GetDecryptedPrivateKey(ctx context.Context, tenantID string, keyVer uint8) (ed25519.PrivateKey, error) {
	lookup := makeKey(tenantID, keyVer)

	// Check in-memory decrypted cache first
	k.mu.RLock()
	cachedPriv, exists := k.keyCache[lookup]
	k.mu.RUnlock()
	if exists {
		return cachedPriv, nil
	}

	// Fetch encrypted record
	rec, err := k.GetTenantKey(ctx, tenantID, keyVer)
	if err != nil {
		return nil, err
	}

	// Decrypt using Master KMS Key
	decryptedBytes, err := k.kmsClient.Decrypt(ctx, rec.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt tenant private key via KMS: %w", err)
	}

	if len(decryptedBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decrypted key has invalid size: expected %d, got %d", ed25519.PrivateKeySize, len(decryptedBytes))
	}

	privKey := ed25519.PrivateKey(decryptedBytes)

	// Store in thread-safe memory cache
	k.mu.Lock()
	k.keyCache[lookup] = privKey
	k.mu.Unlock()

	return privKey, nil
}

// GenerateTenantKey creates a new Ed25519 key pair, encrypts the private key with KMS, and saves it.
func (k *EncryptedKeystore) GenerateTenantKey(ctx context.Context, tenantID string, keyVer uint8) (*TenantKeyRecord, error) {
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Encrypt private key with Master KMS key (Envelope Encryption)
	encryptedPriv, err := k.kmsClient.Encrypt(ctx, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key with Master KMS: %w", err)
	}

	record := &TenantKeyRecord{
		TenantID:            tenantID,
		KeyVersion:          keyVer,
		PublicKey:           pub,
		EncryptedPrivateKey: encryptedPriv,
		CreatedAt:           time.Now().UTC(),
	}

	if err := k.SaveTenantKey(ctx, record); err != nil {
		return nil, err
	}

	// Cache decrypted private key
	lookup := makeKey(tenantID, keyVer)
	k.mu.Lock()
	k.keyCache[lookup] = priv
	k.mu.Unlock()

	return record, nil
}
