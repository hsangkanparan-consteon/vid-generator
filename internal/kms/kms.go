package kms

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// KMSClient defines the interface for Master Key encryption and decryption operations.
type KMSClient interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
	KeyName() string
}

// GCPKMSClient implements KMSClient using Google Cloud Key Management Service.
type GCPKMSClient struct {
	client  *kms.KeyManagementClient
	keyName string // e.g. projects/authenium-prod1/locations/asia-southeast1/keyRings/consteon-qr-ring/cryptoKeys/master-envelope-key
}

// NewGCPKMSClient initializes a Google Cloud KMS client.
func NewGCPKMSClient(ctx context.Context, keyName string) (*GCPKMSClient, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Google Cloud KMS client: %w", err)
	}

	return &GCPKMSClient{
		client:  client,
		keyName: keyName,
	}, nil
}

// Encrypt encrypts plaintext using the Master KMS Key.
func (g *GCPKMSClient) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	req := &kmspb.EncryptRequest{
		Name:      g.keyName,
		Plaintext: plaintext,
	}

	resp, err := g.client.Encrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS encrypt error: %w", err)
	}

	return resp.Ciphertext, nil
}

// Decrypt decrypts ciphertext using the Master KMS Key.
func (g *GCPKMSClient) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	req := &kmspb.DecryptRequest{
		Name:       g.keyName,
		Ciphertext: ciphertext,
	}

	resp, err := g.client.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS decrypt error: %w", err)
	}

	return resp.Plaintext, nil
}

func (g *GCPKMSClient) KeyName() string {
	return g.keyName
}

func (g *GCPKMSClient) Close() error {
	return g.client.Close()
}
