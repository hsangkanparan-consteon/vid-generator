package keystore

import (
	"context"
	"testing"

	"consteon.com/qr-generator/internal/crypto"
	"consteon.com/qr-generator/internal/kms"
)

func TestKeystoreEnvelopeEncryptionAndCaching(t *testing.T) {
	ctx := context.Background()
	mockKMS, err := kms.NewMockKMSClient()
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	store := NewEncryptedKeystore(mockKMS)
	tenantID := "10002000300040"
	keyVer := uint8(1)

	// 1. Generate key
	rec, err := store.GenerateTenantKey(ctx, tenantID, keyVer)
	if err != nil {
		t.Fatalf("failed to generate tenant key: %v", err)
	}

	if rec.TenantID != tenantID || rec.KeyVersion != keyVer {
		t.Errorf("record mismatch: %+v", rec)
	}

	// 2. Fetch record
	fetchedRec, err := store.GetTenantKey(ctx, tenantID, keyVer)
	if err != nil {
		t.Fatalf("failed to fetch tenant key: %v", err)
	}

	if string(fetchedRec.PublicKey) != string(rec.PublicKey) {
		t.Error("public key mismatch")
	}

	// 3. Get decrypted private key and sign message
	privKey, err := store.GetDecryptedPrivateKey(ctx, tenantID, keyVer)
	if err != nil {
		t.Fatalf("failed to get decrypted private key: %v", err)
	}

	msg := []byte("test message for envelope encryption")
	sig, err := crypto.Sign(privKey, msg)
	if err != nil {
		t.Fatalf("failed to sign message: %v", err)
	}

	if !crypto.Verify(rec.PublicKey, msg, sig) {
		t.Error("signature verification failed against generated public key")
	}

	// 4. Test missing tenant error
	_, err = store.GetTenantKey(ctx, "99999999999999", 1)
	if err == nil {
		t.Error("expected error for missing tenant key, got nil")
	}
}
