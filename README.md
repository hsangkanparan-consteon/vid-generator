# Consteon Offline Asymmetric QR Generator & Model Context Protocol (MCP) Server

A Go backend and **Model Context Protocol (MCP)** server built for **Google Cloud Run** with **GCP IAM protection**, **Envelope Encryption via Google Cloud KMS**, **Ed25519 Asymmetric Digital Signatures**, and compact binary codecs for instant offline mobile verification.

---

## 1. Features & Dual Architecture

1. **Model Context Protocol (MCP) Server (2024-11-05 Spec):**
   * **Streamable HTTP POST:** `POST /mcp` (Direct JSON-RPC 2.0 endpoint)
   * **Server-Sent Events (SSE):** `GET /sse` (or `GET /mcp/sse`) + `POST /mcp/messages`
   * **Local Stdio Transport:** `qr-cli mcp` or `server -stdio` for Cursor, Claude Desktop, Antigravity IDE.
2. **Standard RESTful API:**
   * `/v1/qr/location`, `/v1/qr/asset`, `/v1/qr/user`, `/v1/qr/other`, `/v1/keys/generate`, `/v1/public-keys`, `/health`
   * Built for direct Google Apps Script custom functions and Google Sheets formulas.
3. **Asymmetric Security (Ed25519 + KMS):**
   * Backend holds Ed25519 Private Keys protected by Master Google Cloud KMS Key ($0.06/month).
   * Mobile scanners only hold Public Keys. Compliant with **SOC 2 Type II CC6.1/CC6.6** and **ISO/IEC 27001:2022 Control 8.24**.
4. **Target QR Matrix:** **Version 6 ($41 \times 41$ modules)** with **`ecc=M` (15% error recovery)**.

---

## 2. MCP Tools, Resources & Prompts

### Available MCP Tools (`tools/list` & `tools/call`):
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| **`mint_asset_qr`** | `tenant_id`, `unspsc`, `asset_uid` *(opt)*, `key_version` *(opt)* | Mints an Asymmetric Asset QR with 4/6-digit UNSPSC code. Returns 69B generic QR if UID omitted, or 74B if UID present. |
| **`mint_location_qr`** | `tenant_id`, `country_code`, `subtype`, `location_uid` *(opt)* | Mints an Asymmetric Location QR for gates, rooms, toilets, guard stations. |
| **`mint_user_qr`** | `tenant_id`, `vid`, `key_version` *(opt)* | Mints an Asymmetric User / Employee Badge QR for 14-digit numeric VID. |
| **`mint_other_qr`** | `tenant_id`, `subtype`, `entity_id`, `metadata` | Mints an Asymmetric IoT / process QR code. |
| **`verify_qr`** | `url`, `public_key`, `key_version` *(opt)* | Verifies any `https://autsorz/l/3...` URL or raw token string offline. |
| **`generate_tenant_key`** | `tenant_id`, `key_version` *(opt)* | Generates a new Ed25519 key pair in Cloud KMS. |
| **`get_public_key`** | `tenant_id`, `key_version` *(opt)* | Retrieves the public key for mobile device distribution. |

### Available MCP Resources (`resources/list` & `resources/read`):
* `autsorz://schemes`: Cryptographic verification schemes (0=None, 1/2=Legacy, 3=Ed25519).
* `autsorz://unspsc-reference`: Reference table of common 4-digit and 6-digit UNSPSC codes.
* `autsorz://qr-sizing-guide`: QR matrix sizing, error correction, and camera scanning distances.

### Available MCP Prompts (`prompts/list` & `prompts/get`):
* `mint_asset_wizard`: Guides the agent to identify UNSPSC codes and mint asset tags.
* `audit_scanned_qr`: Guides the agent to verify and report on a scanned QR URL.

---

## 3. Directory Structure

```
.
├── cmd/
│   ├── server/                  # Cloud Run HTTP & MCP server entrypoint
│   │   └── main.go
│   └── cli/                     # Admin CLI (includes Stdio MCP runner)
│       └── main.go
├── internal/
│   ├── mcp/                     # Model Context Protocol (MCP) Server Implementation
│   │   ├── types.go             # JSON-RPC 2.0 and MCP protocol definitions
│   │   ├── server.go            # Tools, Resources, and Prompts dispatchers
│   │   ├── http_handler.go      # POST /mcp and GET /sse stream handlers
│   │   ├── stdio.go             # Stdio runner for IDE integration
│   │   └── mcp_test.go          # MCP unit tests
│   ├── api/                     # REST HTTP Handlers, Routing & IAM Middleware
│   │   ├── handler.go
│   │   ├── middleware.go
│   │   └── routes.go
│   ├── codec/                   # Binary codecs (UNSPSC, VID, Location, Header)
│   │   ├── header.go            # 2-byte token header
│   │   ├── uint48.go            # 14-digit VID + ResolveUID40 smart 3-case resolver
│   │   ├── location.go          # Type 1 Location codec (69B/74B)
│   │   ├── asset.go             # Type 2 Asset codec with UNSPSC (69B/74B)
│   │   ├── user.go              # Type 3 User VID codec (72B)
│   │   └── other.go             # Type 4 Extensible codec
│   ├── crypto/                  # Cryptography engine (Ed25519 + Base64URL)
│   ├── kms/                     # Cloud KMS Envelope Encryption (GCP KMS & Mock KMS)
│   └── keystore/                # Multi-tenant key storage & cache
├── pkg/
│   ├── verifier/                # Standalone verifier SDK (offline mobile client)
│   └── sheets/                  # Google Sheets formula generator
├── scripts/
│   ├── setup-kms.sh             # Cloud KMS provisioning script
│   ├── deploy-cloud-run.sh      # Cloud Run deployment script
│   └── apps-script-example.js   # Google Apps Script custom functions
├── Dockerfile
├── go.mod
└── README.md
```

---

## 4. Testing Locally

### Run Unit Tests:
```bash
go test -v ./...
```

### Run MCP Stdio Server Locally:
```bash
go run ./cmd/cli mcp
```

### Connect to Cloud Run MCP Server from AI Clients:
Add to your client MCP configuration (e.g. `claude_desktop_config.json` or Cursor MCP settings):

```json
{
  "mcpServers": {
    "consteon-qr": {
      "url": "https://consteon-qr-generator-xxxx-as.a.run.app/mcp"
    }
  }
}
```

---

## 5. Deploying to Google Cloud Run (`authenium-prod1`)

### Step 1: Login & Set Project
```bash
gcloud auth login
gcloud config set project authenium-prod1
```

### Step 2: Provision Cloud KMS Key
```bash
chmod +x scripts/setup-kms.sh
./scripts/setup-kms.sh
```

### Step 3: Deploy to Cloud Run
```bash
chmod +x scripts/deploy-cloud-run.sh
./scripts/deploy-cloud-run.sh
```
