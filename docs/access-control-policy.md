# Role-Based Access Control (RBAC) Policy

**Standard:** ISO/IEC 27001:2022 Control 5.15 / SOC 2 CC6.3  
**Service:** Consteon VID Generator (`vid-generator`)  

---

## 1. Role Hierarchy & Tool Access Matrix

| MCP Tool | `vid.reader` | `vid.consumer` | `vid.generator` | `vid.admin` | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`validate_vid`** | ✅ | ✅ | ✅ | ✅ | Inspect checksum and extracted address |
| **`get_stock_level`** | ✅ | ✅ | ✅ | ✅ | View available inventory count |
| **`get_vid_by_address`** | ✅ | ✅ | ✅ | ✅ | Lookup VID by address |
| **`allocate_vid`** | ❌ | ✅ | ✅ | ✅ | Claim VIDs from stock for applications |
| **`generate_stock`** | ❌ | ❌ | ✅ | ✅ | Batch-populate available inventory |
| **`import_vids`** | ❌ | ❌ | ❌ | ✅ | Bulk import legacy spreadsheet records |
| **`revoke_vid`** | ❌ | ❌ | ❌ | ✅ | Permanently retire compromised VIDs |

---

## 2. Authentication Flow

1. External caller sends HTTPS request to Cloud Run with `Authorization: Bearer <ID_TOKEN>`.
2. Cloud Run IAM verifies the token signature against Google OAuth keys.
3. The `vid-generator` HTTP middleware extracts the caller identity and evaluates tool authorization against the matrix above.
4. Any violation triggers a `WARNING` severity security event logged to Cloud Logging and BigQuery.
