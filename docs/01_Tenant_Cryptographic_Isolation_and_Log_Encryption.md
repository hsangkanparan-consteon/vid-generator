# Consteon Tenant Cryptographic Isolation & Log Encryption Specification

**Version:** 1.0  
**Date:** September 4, 2026  
**Creator / Owner:** HH (Harry Huang)  
**Status:** Approved / Active Standard  
**Target Systems:** Mobile Apps, Field Scanners, Ingestion Microservices, Audit Log Processors, Decryption Services  

---

## 1. Executive Summary & Zero-Trust Architecture

Consteon enforces mathematical multi-tenant data isolation using asymmetric cryptography and Envelope Encryption. Each organization is identified by a unique **14-digit numeric Tenant ID** (e.g. `62000000000000` for Global Facility, `10002000300040` for commercial tenants).

* **Log Producers (Edge Devices / Mobile / Microservices):** Encrypt logs locally on-device using the target tenant's **Public Key**.
* **Log Consumers (Authorized Audit Backend / Decryption Workers):** Decrypt tenant logs using the tenant's **Private Key** (protected by Google Cloud KMS HSM).
* **Isolation Guarantee:** Tenant A's cryptographic keys cannot decrypt Tenant B's data under any circumstance, even during raw database compromises.

---

## 2. Key Access Specification

### A. How to Access Public Keys (For Encryption)

Log producers and mobile clients require only the **32-byte Ed25519 Public Key**. No private keys or Cloud KMS permissions are needed.

#### Method 1: Firebase Cloud Firestore (Recommended for Mobile & Edge Scanners)
* **Firestore Collection:** `/public_keys/{tenantId}`
* **Security Rules:** Read access is public (`allow read: if true;`), write access is restricted to Cloud Run backend.
* **Document Schema:**
  ```json
  {
    "tenant_id": "62000000000000",
    "latest_version": 1,
    "keys": {
      "1": "8Fy8NgBKJQc+rR85YlZvlwiBFy1lg+88ivJ6zSc3QDE="
    }
  }
  ```
* **Format:** Standard Base64 encoded string (`keys["1"]`).

#### Method 2: Cloud Run REST API (Recommended for Backend Ingestion Pipelines)
```http
GET /v1/public-keys?tenant_id=62000000000000&key_version=1 HTTP/1.1
Host: consteon-qr-generator-63888045044.asia-northeast1.run.app
Authorization: Bearer <GCP_OIDC_TOKEN>
```

---

### B. How to Access Private Keys (For Decryption)

Private keys are protected by **Envelope Encryption** and stored in Google Cloud Storage.

* **GCS Keystore Bucket:** `gs://authenium-prod1-qr-keystore/tenants/{tenantId}_v{keyVersion}.json`
* **Cloud KMS HSM Master Key:** `projects/authenium-prod1/locations/asia-northeast1/keyRings/consteon-qr-ring/cryptoKeys/master-envelope-key`
* **Hardware Protection:** FIPS 140-2 Level 3 Hardware Security Module (HSM) in Tokyo (`asia-northeast1`).

#### Decryption Procedure for Backend Services:
1. Fetch JSON blob from `gs://authenium-prod1-qr-keystore/tenants/{tenantId}_v1.json`.
2. Extract the ciphertext string from `encrypted_private_key_b64`.
3. Call Google Cloud KMS `Decrypt` API using the Master Envelope Key.
4. The output is the raw 64-byte Ed25519 Private Key in volatile memory.

---

## 3. Cryptographic Algorithm: Hybrid Public-Key Encryption (HPKE / ECIES)

Because tenant key pairs are **Ed25519** (RFC 8032), they are converted to **X25519** (Curve25519 Montgomery space, RFC 7748) for Diffie-Hellman Key Exchange and paired with **AES-256-GCM**.

```
                       [ LOG ENCRYPTION FLOW ]
Plaintext Log Payload
         │
         ├───► Ephemeral Keypair Generation (X25519)
         │     ├──► Ephemeral Public Key (32B) ──────────────────────┐
         │     └──► Shared Secret = X25519(ephPriv, TenantX25519Pub) │
         │                               │                           │
         │                               ▼                           │
         │                 HKDF-SHA256 Key Derivation                │
         │                 Derived Key = AES-256-GCM Key             │
         │                               │                           │
         │                               ▼                           │
         └─────────────► AES-256-GCM Authenticated Encryption        │
                                         │                           │
                                         ▼                           ▼
                     [ Output Wire Format: EphemeralPub (32B) + IV (12B) + Ciphertext + Tag ]
```

### Binary Wire Format
```
┌──────────────────────────┬───────────────────┬────────────────────────────────┐
│ Ephemeral PubKey (32B)   │ Nonce / IV (12B)  │ AES-256-GCM Ciphertext + Tag   │
└──────────────────────────┴───────────────────┴────────────────────────────────┘
```

---

## 4. Reference Implementations

### Go Implementation (Encryption & Decryption)

```go
package tenantcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/hkdf"
)

const HKDFInfo = "consteon-tenant-log-v1"

// 1. Convert Ed25519 Public Key to X25519 ECDH Public Key
func Ed25519PublicKeyToX25519(pub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	var point edwards25519.Point
	if _, err := point.SetBytes(pub); err != nil {
		return nil, fmt.Errorf("invalid ed25519 public key: %w", err)
	}
	return ecdh.X25519().NewPublicKey(point.BytesMontgomery())
}

// 2. Convert Ed25519 Private Key to X25519 ECDH Private Key
func Ed25519PrivateKeyToX25519(priv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	h := sha512.Sum512(priv.Seed())
	scalar := h[:32]
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	return ecdh.X25519().NewPrivateKey(scalar)
}

// 3. Encrypt Log for Tenant using Tenant's Public Key
func EncryptTenantLog(tenantEdPub ed25519.PublicKey, tenantID string, plaintext []byte) ([]byte, error) {
	tenantX25519Pub, err := Ed25519PublicKeyToX25519(tenantEdPub)
	if err != nil {
		return nil, err
	}

	// Generate Ephemeral Keypair
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephPubBytes := ephPriv.PublicKey().Bytes()

	// Compute ECDH Shared Secret
	sharedSecret, err := ephPriv.ECDH(tenantX25519Pub)
	if err != nil {
		return nil, err
	}

	// Derive AES-256 Key via HKDF
	hkdfReader := hkdf.New(sha256.New, sharedSecret, ephPubBytes, []byte(HKDFInfo))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, err
	}

	// AES-256-GCM Encryption
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(tenantID))

	// Wire: [ EphemeralPubKey (32B) ] + [ Nonce (12B) ] + [ Ciphertext + Tag ]
	out := append(ephPubBytes, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// 4. Decrypt Log with Tenant's Private Key
func DecryptTenantLog(tenantEdPriv ed25519.PrivateKey, tenantID string, wirePayload []byte) ([]byte, error) {
	if len(wirePayload) < 32+12+16 {
		return nil, errors.New("ciphertext too short")
	}

	ephPubBytes := wirePayload[:32]
	nonce := wirePayload[32:44]
	ciphertext := wirePayload[44:]

	tenantX25519Priv, err := Ed25519PrivateKeyToX25519(tenantEdPriv)
	if err != nil {
		return nil, err
	}

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := tenantX25519Priv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecret, ephPubBytes, []byte(HKDFInfo))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, []byte(tenantID))
}
```

---

### Dart / Flutter Implementation (Client-Side Encryption)

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

Future<Uint8List> encryptLogForTenant({
  required Uint8List tenantEd25519PublicKey,
  required String tenantId,
  required String logJsonText,
}) async {
  final x25519Algo = X25519();
  final aesGcm = AesGcm.with256Bits();

  // 1. Generate Ephemeral KeyPair
  final ephemeralKeyPair = await x25519Algo.newKeyPair();
  final ephemeralPubKey = await ephemeralKeyPair.extractPublicKey();

  // 2. Compute Shared Secret with Tenant X25519 Point
  final sharedSecret = await x25519Algo.sharedSecretKey(
    keyPair: ephemeralKeyPair,
    remotePublicKey: SimplePublicKey(tenantEd25519PublicKey, type: KeyPairType.x25519),
  );

  // 3. Derive AES-256 Key via HKDF
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final derivedAesKey = await hkdf.deriveKey(
    secretKey: sharedSecret,
    nonce: ephemeralPubKey.bytes,
    info: utf8.encode('consteon-tenant-log-v1'),
  );

  // 4. Encrypt with AES-GCM-256
  final secretBox = await aesGcm.encrypt(
    utf8.encode(logJsonText),
    secretKey: derivedAesKey,
    aad: utf8.encode(tenantId),
  );

  // 5. Pack [ EphemeralPub (32B) + Nonce (12B) + Ciphertext + MAC (16B) ]
  final builder = BytesBuilder();
  builder.add(ephemeralPubKey.bytes);
  builder.add(secretBox.nonce);
  builder.add(secretBox.cipherText);
  builder.add(secretBox.mac.bytes);
  return builder.toBytes();
}
```

---

## 5. Security Principles & Compliance

1. **Zero-Knowledge Multi-Tenancy:** Each tenant's data is encrypted with keys unique to their 14-digit identifier.
2. **Cryptographic Shredding:** To irreversibly delete all historical logs for a tenant, deleting their key from Cloud KMS/GCS renders all backups permanently unrecoverable.
3. **End-to-End Encryption (E2EE):** Sensitive patrol, biometric, or asset logs remain encrypted in transit and at rest until accessed by an authorized decryption pipeline.
