package keystore

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"consteon.com/qr-generator/internal/crypto"
	"consteon.com/qr-generator/internal/kms"
)

// GCSStoredRecord is the JSON schema serialized to the GCS bucket.
type GCSStoredRecord struct {
	TenantID            string    `json:"tenant_id"`
	KeyVersion          uint8     `json:"key_version"`
	PublicKeyHex        string    `json:"public_key_hex"`
	PublicKeyB64        string    `json:"public_key_b64"`
	EncryptedPrivateKey string    `json:"encrypted_private_key_b64"`
	CreatedAt           time.Time `json:"created_at"`
}

// GCSKeystore implements the Keystore interface backed by a Google Cloud Storage bucket
// with an in-memory thread-safe LRU cache for decrypted private keys.
type GCSKeystore struct {
	mu              sync.RWMutex
	client          *storage.Client
	bucketName      string
	kmsClient       kms.KMSClient
	firestoreSyncer *FirestoreSyncer
	keyCache        map[string]ed25519.PrivateKey // "tenantID:keyVersion" -> decrypted key
	metaCache       map[string]*TenantKeyRecord   // "tenantID:keyVersion" -> public metadata
}

// SetFirestoreSyncer configures an optional real-time Firestore syncer for public keys.
func (g *GCSKeystore) SetFirestoreSyncer(syncer *FirestoreSyncer) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.firestoreSyncer = syncer
}

// NewGCSKeystore creates a GCS-backed Keystore.
func NewGCSKeystore(ctx context.Context, bucketName string, kmsClient kms.KMSClient) (*GCSKeystore, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCS storage client: %w", err)
	}

	return &GCSKeystore{
		client:     client,
		bucketName: bucketName,
		kmsClient:  kmsClient,
		keyCache:   make(map[string]ed25519.PrivateKey),
		metaCache:  make(map[string]*TenantKeyRecord),
	}, nil
}

func (g *GCSKeystore) objectName(tenantID string, keyVer uint8) string {
	return fmt.Sprintf("tenants/%s_v%d.json", tenantID, keyVer)
}

// SaveTenantKey writes a tenant key record to GCS and updates the local cache.
func (g *GCSKeystore) SaveTenantKey(ctx context.Context, record *TenantKeyRecord) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	stored := GCSStoredRecord{
		TenantID:            record.TenantID,
		KeyVersion:          record.KeyVersion,
		PublicKeyHex:        hex.EncodeToString(record.PublicKey),
		PublicKeyB64:        crypto.EncodeBase64URL(record.PublicKey),
		EncryptedPrivateKey: crypto.EncodeBase64URL(record.EncryptedPrivateKey),
		CreatedAt:           record.CreatedAt,
	}

	jsonData, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key record JSON: %w", err)
	}

	obj := g.client.Bucket(g.bucketName).Object(g.objectName(record.TenantID, record.KeyVersion))
	writer := obj.NewWriter(ctx)
	writer.ContentType = "application/json"

	if _, err := writer.Write(jsonData); err != nil {
		_ = writer.Close()
		return fmt.Errorf("failed to write key record to GCS: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to finalize GCS write: %w", err)
	}

	cacheKey := fmt.Sprintf("%s:%d", record.TenantID, record.KeyVersion)
	g.metaCache[cacheKey] = record

	// Auto-sync public key in standard Base64 to Cloud Firestore for mobile apps
	if g.firestoreSyncer != nil {
		if err := g.firestoreSyncer.SyncPublicKey(ctx, record.TenantID, record.KeyVersion, record.PublicKey); err != nil {
			log.Printf("[WARN] Failed to auto-sync public key to Firestore for tenant %s v%d: %v", record.TenantID, record.KeyVersion, err)
		}
	}

	log.Printf("[GCS_KEYSTORE] Saved tenant key record to gs://%s/%s", g.bucketName, g.objectName(record.TenantID, record.KeyVersion))
	return nil
}

// GenerateTenantKey creates a new Ed25519 keypair, encrypts the private key with Cloud KMS,
// writes the JSON record to GCS, and caches the decrypted key in RAM.
func (g *GCSKeystore) GenerateTenantKey(ctx context.Context, tenantID string, keyVer uint8) (*TenantKeyRecord, error) {
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	encryptedPriv, err := g.kmsClient.Encrypt(ctx, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key with Cloud KMS: %w", err)
	}

	record := &TenantKeyRecord{
		TenantID:            tenantID,
		KeyVersion:          keyVer,
		PublicKey:           pub,
		EncryptedPrivateKey: encryptedPriv,
		CreatedAt:           time.Now().UTC(),
	}

	if err := g.SaveTenantKey(ctx, record); err != nil {
		return nil, err
	}

	g.mu.Lock()
	cacheKey := fmt.Sprintf("%s:%d", tenantID, keyVer)
	g.keyCache[cacheKey] = priv
	g.mu.Unlock()

	return record, nil
}

// GetTenantKey reads the public key record from RAM cache or GCS bucket.
func (g *GCSKeystore) GetTenantKey(ctx context.Context, tenantID string, keyVer uint8) (*TenantKeyRecord, error) {
	cacheKey := fmt.Sprintf("%s:%d", tenantID, keyVer)

	g.mu.RLock()
	rec, exists := g.metaCache[cacheKey]
	g.mu.RUnlock()

	if exists {
		return rec, nil
	}

	// Fetch from GCS
	stored, err := g.fetchFromGCS(ctx, tenantID, keyVer)
	if err != nil {
		return nil, err
	}

	pubBytes, err := crypto.DecodeBase64URL(stored.PublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key in GCS record: %w", err)
	}
	encBytes, err := crypto.DecodeBase64URL(stored.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted private key in GCS record: %w", err)
	}

	rec = &TenantKeyRecord{
		TenantID:            stored.TenantID,
		KeyVersion:          stored.KeyVersion,
		PublicKey:           pubBytes,
		EncryptedPrivateKey: encBytes,
		CreatedAt:           stored.CreatedAt,
	}

	g.mu.Lock()
	g.metaCache[cacheKey] = rec
	g.mu.Unlock()

	return rec, nil
}

// GetDecryptedPrivateKey retrieves the private key from RAM cache or decrypts from GCS via Cloud KMS.
func (g *GCSKeystore) GetDecryptedPrivateKey(ctx context.Context, tenantID string, keyVer uint8) (ed25519.PrivateKey, error) {
	cacheKey := fmt.Sprintf("%s:%d", tenantID, keyVer)

	g.mu.RLock()
	cachedPriv, exists := g.keyCache[cacheKey]
	g.mu.RUnlock()

	if exists {
		return cachedPriv, nil
	}

	rec, err := g.GetTenantKey(ctx, tenantID, keyVer)
	if err != nil {
		return nil, err
	}

	decryptedPriv, err := g.kmsClient.Decrypt(ctx, rec.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt tenant private key via Cloud KMS: %w", err)
	}

	g.mu.Lock()
	g.keyCache[cacheKey] = decryptedPriv
	g.mu.Unlock()

	return decryptedPriv, nil
}

func (g *GCSKeystore) fetchFromGCS(ctx context.Context, tenantID string, keyVer uint8) (*GCSStoredRecord, error) {
	obj := g.client.Bucket(g.bucketName).Object(g.objectName(tenantID, keyVer))
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %s (version %d) in GCS", ErrTenantKeyNotFound, tenantID, keyVer)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read key record from GCS: %w", err)
	}

	var stored GCSStoredRecord
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GCS key record: %w", err)
	}

	return &stored, nil
}
