package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"consteon.com/qr-generator/internal/codec"
	"consteon.com/qr-generator/internal/crypto"
	"consteon.com/qr-generator/internal/keystore"
	"consteon.com/qr-generator/internal/kms"
)

func main() {
	startTime := time.Now()

	kmsKeyName := "projects/authenium-prod1/locations/asia-northeast1/keyRings/consteon-qr-keyring/cryptoKeys/master-envelope-key"
	bucketName := "authenium-prod1-qr-keystore"

	ctx := context.Background()
	kmsClient, err := kms.NewGCPKMSClient(ctx, kmsKeyName)
	if err != nil {
		panic(fmt.Sprintf("failed to init KMS: %v", err))
	}
	defer kmsClient.Close()

	ks, err := keystore.NewGCSKeystore(ctx, bucketName, kmsClient)
	if err != nil {
		panic(fmt.Sprintf("failed to init keystore: %v", err))
	}

	tenantID := "62000000000000"
	var keyVersion uint8 = 1

	record, err := ks.GetTenantKey(ctx, tenantID, keyVersion)
	if err != nil {
		panic(fmt.Sprintf("failed to get tenant key record: %v", err))
	}

	privKey, err := ks.GetDecryptedPrivateKey(ctx, tenantID, keyVersion)
	if err != nil {
		panic(fmt.Sprintf("failed to get decrypted private key: %v", err))
	}

	pubKey := ed25519.PublicKey(record.PublicKey)

	fmt.Printf("Loaded Signing Key for Tenant %s (KeyVersion %d)\nPublic Key: %x\n", tenantID, keyVersion, pubKey)

	// Read VIDs
	rawVIDs, err := os.ReadFile("/Users/harryhuang/.gemini/antigravity/brain/4f65e777-505c-481a-9961-011a8f0dd92b/scratch/vids_49729.json")
	if err != nil {
		panic(err)
	}

	var vids []string
	if err := json.Unmarshal(rawVIDs, &vids); err != nil {
		panic(err)
	}

	total := len(vids)
	fmt.Printf("Starting parallel minting of %d VIDs in RFC 9285 Base45...\n", total)

	results := make([]string, total)
	header := codec.Header{
		Type:          codec.TypeUser,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    keyVersion,
	}
	headerBytes := codec.EncodeHeader(header)

	var wg sync.WaitGroup
	workers := 16
	chunkSize := (total + workers - 1) / workers

	for w := 0; w < workers; w++ {
		start := w * chunkSize
		end := start + chunkSize
		if end > total {
			end = total
		}
		if start >= total {
			break
		}

		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			for i := s; i < e; i++ {
				vid := vids[i]
				payloadBytes, err := codec.EncodeUserPayload(codec.UserPayload{VID: vid})
				if err != nil {
					panic(fmt.Sprintf("invalid vid at %d: %v", i, err))
				}
				message := append(headerBytes[:], payloadBytes[:]...)
				sig := ed25519.Sign(privKey, message)

				// Verify
				if !ed25519.Verify(pubKey, message, sig) {
					panic(fmt.Sprintf("verification failed for vid %s at index %d", vid, i))
				}

				fullToken := append(message, sig...)
				b45Token := "3" + crypto.EncodeBase45(fullToken)
				results[i] = b45Token
			}
		}(start, end)
	}

	wg.Wait()
	duration := time.Since(startTime)
	fmt.Printf("Successfully minted and verified all %d tokens in %v!\n", total, duration)

	// Write TSV file
	outFile, err := os.Create("/Users/harryhuang/.gemini/antigravity/brain/4f65e777-505c-481a-9961-011a8f0dd92b/scratch/tokens_49729_b45.tsv")
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	for _, token := range results {
		outFile.WriteString(token + "\n")
	}

	fmt.Printf("Written %d tokens to scratch/tokens_49729_b45.tsv\n", len(results))
	fmt.Printf("Row 2 (index 0): %s\n", results[0])
	fmt.Printf("Row 49730 (index %d): %s\n", len(results)-1, results[len(results)-1])
}
