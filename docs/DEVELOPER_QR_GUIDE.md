# Consteon Scheme 3 QR Ecosystem: Complete Developer & MCP Guide

This document is the comprehensive technical reference for software engineers, security architects, and AI agent developers building against the **Consteon Scheme 3 Offline QR Code System**, **Hybrid Scheme 1 & 3 Architecture**, **Google Cloud KMS Keystore**, **Redis Bloom Deduplication Engine**, and the **Model Context Protocol (MCP) Server**.

---

## Table of Contents

1. [Architecture & Cryptographic Principles](#1-architecture--cryptographic-principles)
2. [Hybrid Scheme 1 vs. Scheme 3 Architecture](#2-hybrid-scheme-1-vs-scheme-3-architecture)
3. [Token Wire Layout & Binary Specifications](#3-token-wire-layout--binary-specifications)
4. [Key Management, Envelope Encryption & Key Rotation](#4-key-management-envelope-encryption--key-rotation)
5. [Redis Bloom Filter & Zero-Redundancy Deduplication](#5-redis-bloom-filter--zero-redundancy-deduplication)
6. [Model Context Protocol (MCP) Integration & Live Links](#6-model-context-protocol-mcp-integration--live-links)
7. [MCP Tools Reference & Examples](#7-mcp-tools-reference--examples)
8. [HTTP REST API Reference](#8-http-rest-api-reference)
9. [Client Verification (Dart/Flutter, Go, Python)](#9-client-verification-dartflutter-go-python)
10. [SOC 2 & ISO 27001 Compliance Matrix](#10-soc-2--iso-27001-compliance-matrix)

---

## 1. Architecture & Cryptographic Principles

Consteon Scheme 3 is an **offline-first, tamper-proof, asymmetric cryptographic QR system** designed for physical facilities, asset management, and user identification.

```
┌────────────────────────────────────────────────────────────────────────┐
│                          CONSTEON QR ECOSYSTEM                         │
├─────────────────────────┬──────────────────────┬───────────────────────┤
│   MINTING / BACKEND     │   STORAGE & DEDUP    │   SCANNER / CLIENT    │
│  (Cloud Run & KMS)      │   (Redis Bitsets)    │   (Flutter / Web)     │
│                         │                      │                       │
│  • Ed25519 (RFC 8032)   │  • Zero-redundancy   │  • 100% Offline       │
│  • Google Cloud KMS     │  • Bloom filter      │  • < 1 ms verify      │
│  • MCP Server           │  • Exact Set index   │  • Public key cache   │
└─────────────────────────┴──────────────────────┴───────────────────────┘
```

### Key Security & Design Properties
* **Zero PII Exposure:** Tokens contain no names, emails, phone numbers, or passwords. Only high-entropy pseudonymous IDs or numeric VIDs are stored.
* **Mathematical Tamper-Proofing:** Every token is signed with a 64-byte (512-bit) **Ed25519 digital signature** or authenticated via cryptographic MAC. Modifying a single bit invalidates the token.
* **Instant Offline Verification:** Mobile scanners verify authenticity and decode payloads in **< 1 millisecond** using locally cached public keys without any database lookups.

---

## 2. Hybrid Scheme 1 vs. Scheme 3 Architecture

To accommodate both **ultra-compact mobile badge displays** and **high-security physical facility access**, the system supports a **Hybrid Architecture**:

```
                                  ┌───────────────────────────┐
                                  │ Scanned Code from Camera  │
                                  └─────────────┬─────────────┘
                                                │
                               ┌────────────────┴────────────────┐
                               ▼                                 ▼
                     [ Starts with '1' ]               [ Starts with '3' ]
                     Scheme 1 (Symmetric)              Scheme 3 (Asymmetric)
                     • 27 characters                   • 97 characters
                     • 25x25 matrix (Chunky)           • 33x33 / 41x41 matrix
                     • Fast phone-to-phone scans       • FIPS 186-5 Ed25519 signature
                               │                                 │
                               └────────────────┬────────────────┘
                                                ▼
                               ┌─────────────────────────────────┐
                               │       Unified QRResult          │
                               │  • isValid: true                │
                               │  • vid: "84934291271249"        │
                               │  • scheme: 1 or 3               │
                               └─────────────────────────────────┘
```

### Side-by-Side Comparison

| Feature / Metric | Scheme 1 (Symmetric Compact) | Scheme 3 (Asymmetric Ed25519) |
| :--- | :---: | :---: |
| **Token Length** | **27 Characters** (e.g. `1V9F11wJxR-qt3-9E68Qcqwxz6O`) | **97 Characters** (e.g. `3MQEhH4_bMrF...`) |
| **QR Code Matrix** | **$25 \times 25$ Matrix (Version 2)** | **$33 \times 33$ (ECC L)** / **$41 \times 41$ (ECC M)** |
| **Visual Density** | Ultra-chunky, huge blocks | Dense grid, standard blocks |
| **Information Stored** | 14-Digit VID + Key Version | 14-Digit VID + Key Version |
| **Information Loss** | **Zero Data Loss** | **Zero Data Loss** |
| **Ideal Use Case** | Dynamic phone screens, digital employee badges | Physical printed door stickers, audited facility gates |

---

## 3. Token Wire Layout & Binary Specifications

Every Scheme 3 token is prefixed with ASCII character `'3'`, followed by Base64URL-encoded binary bytes:

```
[ Header (2 Bytes) ] + [ Binary Payload (N Bytes) ] + [ Ed25519 Signature (64 Bytes) ]
```

### 1. Header Structure (2 Bytes)

```
Byte 0:
┌───────────────────────────┬───────────────────────────┐
│     QR Type (4 bits)      │   Format Version (4 bits) │
│  0x1=Location, 0x2=Asset  │       0x1 = Version 1     │
│  0x3=User,     0x4=Other  │       (Supports 0..15)    │
└───────────────────────────┴───────────────────────────┘

Byte 1:
┌───────────────────────────────────────────────────────┐
│                 Key Version (8 bits)                  │
│       1..255 (Identifies Tenant Signing Key)          │
└───────────────────────────────────────────────────────┘
```

### 2. Payload Layouts & Unified RFC 9285 (Base45) Standard

All Scheme 3 QR codes are prefixed with ASCII character `'3'`, followed by **RFC 9285 (Base45)** alphanumeric characters. Dual-decoding fallback ensures seamless compatibility with legacy Base64URL tokens.

#### Type 1: Location QR (85 Raw Bytes $\to$ 129 Base45 Chars $\to$ Version 5, $37 \times 37$)
* **Header (2B):** `0x11` (Type 1, Ver 1), `KeyVersion` (1B)
* **Payload (19B):**
  * `Bytes 0..1` (2B): `CountryCode` (uint16 big-endian, e.g. `62` for Indonesia)
  * `Byte 2` (1B): `Subtype` (uint8: `0=unknown`, `1=portal`, `2=guard_station`, `3=room`, `4=toilet`, `5=gate`, `6=checkpoint`)
  * `Bytes 3..18` (16B): `LocationIDRaw` (16 cryptographic random bytes)
* **Signature (64B):** Ed25519 signature over Header + Payload (21 bytes).
* **QR Matrix:** **Version 5 ($37 \times 37$, ECC L)** — 18.6% fewer blocks than Base64 Byte Mode.

#### Type 2: Asset QR (85 Raw Bytes $\to$ 129 Base45 Chars $\to$ Version 5, $37 \times 37$)
* **Header (2B):** `0x21` (Type 2, Ver 1), `KeyVersion` (1B)
* **Payload (19B):**
  * `Bytes 0..2` (3B): `UNSPSC` (uint24 big-endian, e.g. `241118` for Gas Cylinders / `432115` for Computers)
  * `Bytes 3..18` (16B): `AssetIDRaw` (16 cryptographic random bytes)
* **Signature (64B):** Ed25519 signature over Header + Payload (21 bytes).
* **QR Matrix:** **Version 5 ($37 \times 37$, ECC L)** — 18.6% fewer blocks than Base64 Byte Mode.

#### Type 3: User VID QR (72 Raw Bytes $\to$ 109 Base45 Chars $\to$ Version 4, $33 \times 33$)
* **Header (2B):** `0x31` (Type 3, Ver 1), `KeyVersion` (1B)
* **Payload (6B):** `VID` (uint48 big-endian representing 14-digit numeric string, e.g. `64446444131342`)
* **Signature (64B):** Ed25519 signature over Header + Payload (8 bytes).
* **QR Matrix:** **Version 4 ($33 \times 33$, ECC L)** — 35.2% fewer blocks than Base64 Byte Mode.

---

## 4. Unified RFC 9285 (Base45) Compact QR Standard

Consteon Scheme 3 unifies all QR types on **RFC 9285 (Base45 Encoding)** — the international standard developed for the EU Digital Identity Certificate and ICAO e-Passports.

### Why Base45 Yields Ultra-Low Density
Standard QR codes (ISO/IEC 18004) support a native **Alphanumeric Mode** that compresses pairs of characters into **11 bits instead of 16 bits** (5.5 bits/char vs 8.0 bits/char):

```
┌─────────────────────────┬──────────────┬───────────────────┬────────────────────────────────────┐
│         QR Type         │  Raw Bytes   │ Base45 Characters │           QR Code Matrix           │
├─────────────────────────┼──────────────┼───────────────────┼────────────────────────────────────┤
│ User VID QR (Type 3)    │ 72 Bytes     │ 109 Characters    │ Version 4 ($33 \times 33$) (ECC L) │
│ Location QR (Type 1)    │ 85 Bytes     │ 129 Characters    │ Version 5 ($37 \times 37$) (ECC L) │
│ Asset QR (Type 2)       │ 85 Bytes     │ 129 Characters    │ Version 5 ($37 \times 37$) (ECC L) │
└─────────────────────────┴──────────────┴───────────────────┴────────────────────────────────────┘
```

```
[ Raw Cryptographic Bytes ] (Header + Payload + 64B Ed25519 Sig)
              │
              ▼ RFC 9285 Base45 + '3' Scheme Prefix
[ Alphanumeric Characters ] ('3' + 0-9, A-Z, $, %, *, +, -, ., /, :)
              │
              ▼ ISO/IEC 18004 Alphanumeric Mode
[ Compact Version 4 / Version 5 QR Code ] ──► Chunkier blocks, scans instantly in low light!
```

## 4. Key Management, Envelope Encryption & Key Rotation

### Envelope Encryption Architecture
Private signing keys are never stored in plaintext on disk, databases, or environment variables.

```
┌────────────────────────────────────────────────────────────┐
│                  Google Cloud KMS (HSM)                    │
│             FIPS 140-2 Level 3 Master Key (KEK)            │
└─────────────────────────────┬──────────────────────────────┘
                              │ Encrypts / Decrypts
                              ▼
┌────────────────────────────────────────────────────────────┐
│                      Cloud Keystore                        │
│  Encrypted Blob = AES-GCM-256(Ed25519 Private Key, DEK)    │
│  Tenant Public Key = Stored in Firestore / Memory          │
└────────────────────────────────────────────────────────────┘
```

### Multi-Tenant Key Isolation
* Every organization/tenant is assigned a unique **14-digit numeric Tenant ID** (e.g. `62000000000000` for Global Facility, `39802730935703` for client tenants).
* Keys are mathematically isolated: tokens signed by Tenant A will fail verification under Tenant B.

### Key Rotation Procedure (`KeyVersion 1..255`)
1. **Nominal Frequency:** Every **3 to 5 years** (or on-demand if a compromise is suspected).
2. **Backward Compatibility:** When a new key is minted (`POST /v1/keys/generate` with `key_version=2`):
   * Newly printed stickers use `KeyVersion = 2`.
   * Existing physical stickers with `KeyVersion = 1` **continue to work seamlessly** because mobile scanners hold a keyring map `{1: pubkey1, 2: pubkey2}`.
3. **Capacity:** Up to 255 distinct key versions per tenant (> 700 years of operation).

### Real-Time Cloud Firestore Synchronization
Whenever a new tenant key is created or rotated via MCP (`generate_tenant_key`) or REST API (`POST /v1/keys/generate`), the Cloud Run backend **automatically syncs the public key in Base64 format** directly to Cloud Firestore:
* **Collection:** `/public_keys/{tenantId}`
* **Schema:**
  ```json
  {
    "tenant_id": "00000000000000",
    "latest_version": 1,
    "keys": {
      "1": "PZiIHMtn2bLljR3Oq0JRZGs0SDXdkoeEexVSdSSPLW8="
    }
  }
  ```
* Mobile scanners automatically fetch or cache these public keys for instant offline signature verification.

---

## 5. Redis Bloom Filter & Zero-Redundancy Deduplication

To ensure that no two physical doors, rooms, assets, or employee badges ever share duplicate IDs, the system includes an industrial-grade deduplication engine (`internal/dedup`).

```
                              ┌──────────────────────┐
                              │ Mint Request / Check │
                              └──────────┬───────────┘
                                         │
                                         ▼
                     ┌───────────────────────────────────────┐
                     │ Fast Bloom Filter (Redis Bitset)      │
                     │  7 Hash Functions (xxhash + fnv1a)    │
                     └───────────────────┬───────────────────┘
                                         │
                        ┌────────────────┴────────────────┐
                        ▼                                 ▼
                 [ Bit is 0 (NO) ]                 [ Bits are 1 (MAYBE) ]
                        │                                 │
                        ▼                                 ▼
             ID is 100% Unique!              Confirm with Exact Redis Set
             Atomic SADD & SETBIT            SISMEMBER tenant:{id}:locations
                        │                                 │
                        ▼                        ┌────────┴────────┐
             Return Generated ID                 ▼                 ▼
                                         [ Already Exists ]   [ False Positive ]
                                         Reject: 409 Conflict  Atomic Register
```

### Memory Footprint Math
Standard Google Cloud Memorystore / Valkey does not need custom C modules. It uses native bit operations (**`SETBIT` / `GETBIT`**):
* **10,000,000 items at 1% False Positive Rate:** Requires only **~11.98 MB of RAM**.
* **Zero Redundancy Guarantee:** The exact Redis Set (`SADD`) guarantees that collision probability is **0%**.
* **Collision Retry Loop:** If an auto-generated random ID is already registered, the generator automatically retries up to 10 times.

---

## 6. Model Context Protocol (MCP) Integration & Live Links

The Consteon QR service exposes a native **Model Context Protocol (MCP)** server conforming to the JSON-RPC 2.0 specification.

### Live Production MCP Endpoints

| Resource | Live Endpoint URL | Protocol / Method |
| :--- | :--- | :--- |
| **Live MCP JSON-RPC 2.0** | `https://consteon-qr-generator-63888045044.asia-northeast1.run.app/mcp` | `POST` (JSON-RPC 2.0) |
| **Live MCP SSE Stream** | `https://consteon-qr-generator-63888045044.asia-northeast1.run.app/sse` | `GET` (Server-Sent Events) |
| **Custom Domain URL** | `https://consteon-qr-generator-mtabakupaq-an.a.run.app/mcp` | `POST` (Custom Domain) |
| **Health Check** | `https://consteon-qr-generator-63888045044.asia-northeast1.run.app/health` | `GET` (Liveness probe) |
| **GCP Region & Project** | Tokyo (`asia-northeast1`) \| Project: `authenium-prod1` | Managed Cloud Run |

---

### Connection Modes

#### 1. Remote Cloud Run Endpoint (SSE / HTTP)
AI agents and external services connect over HTTPS using a **Google Cloud OIDC Bearer Token**:

```bash
# 1. Obtain Google Cloud OIDC identity token
TOKEN=$(gcloud auth print-identity-token)

# 2. Invoke MCP JSON-RPC tool directly via cURL
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "mint_location_qr",
      "arguments": {
        "tenant_id": "62000000000000",
        "country_code": 62,
        "subtype": "0",
        "location_uid": "generate"
      }
    }
  }' \
  https://consteon-qr-generator-63888045044.asia-northeast1.run.app/mcp
```

#### 2. Local IDE Stdio Mode (Cursor, Claude Desktop, Antigravity)
Run the binary directly via stdin/stdout:
```bash
./qr-server -stdio
```

**Claude Desktop / Cursor Configuration (`mcpSettings.json`):**
```json
{
  "mcpServers": {
    "consteon-qr-local": {
      "command": "/path/to/qr-server",
      "args": ["-stdio"],
      "env": {
        "USE_MOCK_KMS": "true",
        "REDIS_HOST": "127.0.0.1",
        "REDIS_PORT": "6379"
      }
    },
    "consteon-qr-cloud": {
      "url": "https://consteon-qr-generator-63888045044.asia-northeast1.run.app/sse",
      "headers": {
        "Authorization": "Bearer YOUR_GOOGLE_OIDC_IDENTITY_TOKEN"
      }
    }
  }
}
```

---

## 7. MCP Tools Reference & Examples

### 1. `mint_location_qr`
Mints a Location QR code with cryptographic proof and deduplication.

* **Arguments:**
  * `tenant_id` *(string, default: "00000000000000")*: 14-digit tenant ID.
  * `country_code` *(number, default: 360)*: ISO 3166-1 numeric code (e.g. `62`).
  * `subtype` *(string)*: `"0"`, `"portal"`, `"guard_station"`, `"room"`, `"toilet"`, `"gate"`, `"checkpoint"`.
  * `location_uid` *(string, optional)*: `"generate"`, `"random"`, or a specific ID string.
  * `key_version` *(number, default: 1)*: Signing key version.

**Example Tool Call:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "mint_location_qr",
    "arguments": {
      "tenant_id": "39802730935703",
      "country_code": 62,
      "subtype": "gate",
      "location_uid": "generate"
    }
  }
}
```

**Example Response:**
```json
{
  "tenant_id": "39802730935703",
  "type": "location",
  "key_version": 1,
  "raw_bytes_count": 85,
  "unencrypted_id": "0sJ4sy7f4FQVE4-rYyd95bg",
  "location_id": "0sJ4sy7f4FQVE4-rYyd95bg",
  "token_base64url": "3EQEAPgWwnizLt_gVBUTj6tjJ33lulWEgJ7u89y6oDkJ1wYOoNmkQUxA3j8wFtu0tVrwNkC5YhEAp7U2pcAREAOP5r4Dbky-gsl7GvC5A3lXSAAfmDw",
  "full_url": "https://autsorz/l/3EQEAPgWwnizLt_gVBUTj6tjJ33lulWEgJ7u89y6oDkJ1wYOoNmkQUxA3j8wFtu0tVrwNkC5YhEAp7U2pcAREAOP5r4Dbky-gsl7GvC5A3lXSAAfmDw",
  "qr_formula": "=IMAGE(\"https://api.qrserver.com/v1/create-qr-code/?size=310x310&ecc=M&margin=1&data=\" & ENCODEURL(G2))"
}
```

---

### 2. `mint_asset_qr`
Mints an Asset QR code with UNSPSC classification.

* **Arguments:**
  * `tenant_id` *(string)*: 14-digit tenant ID.
  * `unspsc` *(string)*: 4 or 6-digit UNSPSC code (e.g. `"432115"`).
  * `asset_uid` *(string, optional)*: `"generate"`, `"random"`, or specific ID.

**Example Tool Call:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "mint_asset_qr",
    "arguments": {
      "tenant_id": "39802730935703",
      "unspsc": "432115",
      "asset_uid": "generate"
    }
  }
}
```

---

### 3. `verify_and_decrypt_qr`
Verifies the cryptographic signature of any scanned QR code and unpacks all binary fields.

* **Arguments:**
  * `token` *(string)*: Raw token (`3...` or `1...`) or full URL (`https://autsorz/l/...`).
  * `tenant_id` *(string, optional)*: Tenant ID for public key lookup (defaults to `62000000000000`).

**Example Tool Call:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "verify_and_decrypt_qr",
    "arguments": {
      "token": "3EQEAPgWwnizLt_gVBUTj6tjJ33lulWEgJ7u89y6oDkJ1wYOoNmkQUxA3j8wFtu0tVrwNkC5YhEAp7U2pcAREAOP5r4Dbky-gsl7GvC5A3lXSAAfmDw",
      "tenant_id": "39802730935703"
    }
  }
}
```

**Example Response:**
```json
{
  "is_valid": true,
  "is_registered": true,
  "scheme": 3,
  "type": "location",
  "key_version": 1,
  "country_code": 62,
  "subtype": "gate",
  "location_id": "0sJ4sy7f4FQVE4-rYyd95bg",
  "unencrypted_id": "0sJ4sy7f4FQVE4-rYyd95bg",
  "raw_bytes_count": 85,
  "signature_hex": "95612027bbbcf72ea80e4275c183a83669105310378fcc05b6ed2d56bc0d902e58844029ed4da970044400e3f9af80db932fa0b25ec6bc2e40de55d20007e60f"
}
```

---

## 8. HTTP REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/v1/qr/location` | Mint single Location QR code |
| `POST` | `/v1/qr/asset` | Mint single Asset QR code |
| `POST` | `/v1/qr/user` | Mint single User VID QR code |
| `POST` | `/v1/qr/decode` | Verify signature and decode any Scheme 3 or Scheme 1 QR token |
| `POST` | `/v1/keys/generate` | Generate / rotate a new Ed25519 key version for a tenant |
| `GET` | `/v1/keys/public` | Retrieve the public key for mobile app synchronization |
| `POST` | `/v1/batch/location` | Batch mint up to 10,000 Location QR codes |
| `POST` | `/v1/batch/asset` | Batch mint up to 10,000 Asset QR codes |
| `POST` | `/v1/batch/user` | Batch mint up to 50,000 User VID QR codes |

---

## 9. Client Verification (Dart/Flutter, Go, Python)

### Dart / Flutter Offline Verification Snippet
```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

Future<bool> verifyAndDecodeQR(String qrToken, List<int> tenantPublicKeyBytes) async {
  // 1. Extract prefix and strip scheme
  int scheme = int.tryParse(qrToken[0]) ?? -1;
  String b64 = qrToken.substring(1).replaceAll('-', '+').replaceAll('_', '/');
  while (b64.length % 4 != 0) b64 += '=';
  Uint8List rawBytes = base64.decode(b64);

  if (scheme == 3) {
    // Scheme 3: Asymmetric Ed25519 Verification
    int messageLen = rawBytes.length - 64;
    List<int> messageBytes = rawBytes.sublist(0, messageLen);
    List<int> signatureBytes = rawBytes.sublist(messageLen);

    final algorithm = Ed25519();
    final publicKey = SimplePublicKey(tenantPublicKeyBytes, type: KeyPairType.ed25519);
    final signature = Signature(signatureBytes, publicKey: publicKey);
    
    bool isValid = await algorithm.verify(messageBytes, signature: signature);
    if (!isValid) return false;

    print('Scheme 3 Verification Successful!');
    return true;
  } else if (scheme == 1) {
    // Scheme 1: Symmetric Compact Low-Density
    int vidInt = (rawBytes[1] << 40) | (rawBytes[2] << 32) | (rawBytes[3] << 24) |
                 (rawBytes[4] << 16) | (rawBytes[5] << 8) | rawBytes[6];
    print('Scheme 1 VID: ${vidInt.toString().padLeft(14, '0')}');
    return true;
  }
  return false;
}
```

---

## 10. SOC 2 & ISO 27001 Compliance Matrix

* **Cryptography (ISO 27001 A.8.24):** Ed25519 (RFC 8032, FIPS 186-5 compliant).
* **Key Lifecycle (SOC 2 CC6.1 & CC6.7):** Google Cloud KMS HSM (FIPS 140-2 Level 3).
* **Zero PII Exposure (ISO 27001 A.8.11):** Privacy by Design tokenization.
* **Tamper Proofing (SOC 2 CC6.6):** 512-bit digital signatures on all wire tags.
