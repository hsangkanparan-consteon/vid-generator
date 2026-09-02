package keystore

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strconv"

	"cloud.google.com/go/firestore"
)

// FirestoreSyncer synchronizes public keys in real-time to Cloud Firestore for mobile client consumption.
type FirestoreSyncer struct {
	client    *firestore.Client
	projectID string
}

// NewFirestoreSyncer initializes a new Firestore public key syncer.
func NewFirestoreSyncer(ctx context.Context, projectID string) (*FirestoreSyncer, error) {
	if projectID == "" {
		return nil, nil
	}

	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize firestore client: %w", err)
	}

	return &FirestoreSyncer{
		client:    client,
		projectID: projectID,
	}, nil
}

// Close releases the Firestore client resources.
func (f *FirestoreSyncer) Close() error {
	if f != nil && f.client != nil {
		return f.client.Close()
	}
	return nil
}

// SyncPublicKey writes or updates the tenant's public key in standard Base64 format in Firestore.
// Path: /public_keys/{tenantId}
func (f *FirestoreSyncer) SyncPublicKey(ctx context.Context, tenantID string, keyVersion uint8, pubKey []byte) error {
	if f == nil || f.client == nil {
		return nil
	}

	b64Key := base64.StdEncoding.EncodeToString(pubKey)
	docRef := f.client.Collection("public_keys").Doc(tenantID)

	// Merge field updates: set tenant_id, latest_version, and keys.<version>
	updates := map[string]interface{}{
		"tenant_id":      tenantID,
		"latest_version": int64(keyVersion),
		"keys": map[string]interface{}{
			strconv.Itoa(int(keyVersion)): b64Key,
		},
	}

	_, err := docRef.Set(ctx, updates, firestore.MergeAll)
	if err != nil {
		return fmt.Errorf("firestore set error for tenant %s: %w", tenantID, err)
	}

	log.Printf("[INFO] Synchronized Public Key to Firestore: /public_keys/%s (version %d, base64: %s)", tenantID, keyVersion, b64Key)
	return nil
}
