# Consteon VID Generator & Model Context Protocol (MCP) Server

A high-performance Go backend and **Model Context Protocol (MCP)** server built for **Google Cloud Run** with **GCP IAM protection**, **Google Cloud Firestore (`vid-registry`)**, **BigQuery 7-Year Audit Archiving**, and **CSPRNG Cryptographic Randomness**.

---

## 1. Overview & Architecture

* **Target Deployment:** Google Cloud Run (Serverless, scales to 0, sub-100ms cold starts).
* **Database:** Google Cloud Firestore in Native mode (`vid-registry` in `authenium-prod1`).
* **Uniqueness Guarantee:** Address string is the Firestore Document ID, inherently preventing duplicate addresses across concurrent writers.
* **VID Format:** 14-digit numeric string (12-digit payload + 2-digit MOD-100 checksum).
* **Compliance:** Fully aligned with **SOC 2 Type II CC4.1/CC6.1/CC6.3** and **ISO/IEC 27001:2022 Controls 8.2, 8.16, 8.24**.

---

## 2. MCP Protocols & Transports (2024-11-05 Spec)

1. **Streamable HTTP POST:** `POST /mcp` (Direct JSON-RPC 2.0 endpoint)
2. **Server-Sent Events (SSE):** `GET /sse` + `POST /mcp`
3. **Local Stdio Transport:** `vid-cli mcp` for Cursor, Claude Desktop, Antigravity IDE.
4. **Container Health Probes:** `GET /health`

---

## 3. Available MCP Tools

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| **`generate_stock`** | `country_code`, `count` | Batch-generates unique 14-digit VIDs and commits to Firestore available stock. |
| **`allocate_vid`** | `country_code`, `count` *(opt)*, `requester` *(opt)* | Atomically claims available VIDs from stock for applications. |
| **`validate_vid`** | `vid` | Validates checksum, extracts address/cluster/position, and checks DB status. |
| **`get_vid_by_address`** | `address` | Looks up a VID and its lifecycle status by its 12-digit numeric address. |
| **`import_vids`** | `vids` (array) | Bulk-imports legacy spreadsheet VIDs as `in_use` with automatic duplicate skipping. |
| **`get_stock_level`** | `country_code` | Checks real-time stock inventory levels (available, allocated, in_use, revoked). |
| **`revoke_vid`** | `vid`, `reason` | Permanently revokes a VID while retaining the address to ensure it is never reused. |

---

## 4. Directory Structure

```
.
├── Dockerfile                        # Multi-stage Go 1.23 build -> Distroless image (~25MB)
├── Makefile                          # Build, test, run, and deploy shortcuts
├── go.mod
├── README.md
├── cmd/
│   ├── server/                       # Cloud Run HTTP & MCP Server entrypoint
│   │   └── main.go
│   └── cli/                          # Admin CLI & Stdio MCP Runner
│       └── main.go
├── internal/
│   ├── config/                       # Environment & GCP configuration
│   ├── vid/                          # VID Core Engine (Math, Generator, Validator, Seed Table)
│   ├── db/                           # Firestore Database Layer (vid-registry)
│   ├── mcp/                          # Model Context Protocol Engine (JSON-RPC 2.0 & SSE)
│   ├── middleware/                   # Audit Logging (Cloud Logging) & RBAC Middlewares
│   └── migration/                    # Bulk CSV legacy importer
├── pkg/
│   └── vidmath/                      # Reusable mathematical address & checksum library
├── tests/
│   └── validator_test.go             # Verification tests against spreadsheet samples
├── docs/                             # ISO 27001 & SOC 2 Compliance Documentation
└── deploy/
    └── terraform/                    # Infrastructure as Code (Cloud Run, Firestore, BigQuery)
```

---

## 5. Quick Start & Testing

### Run Unit Tests
```bash
go test -v ./tests/...
```

### Run CLI Locally
```bash
# Generate 5 sample VIDs for Indonesia (62)
go run ./cmd/cli generate -country 62 -count 5

# Validate a 14-digit VID
go run ./cmd/cli validate -vid 11306930191372
```

### Run Server Locally
```bash
export PROJECT_ID=authenium-prod1
export DATABASE_ID=vid-registry
go run ./cmd/server
```
