# Information Classification & Handling Policy

**Standard:** ISO/IEC 27001:2022 Control 8.2 & SOC 2 CC6.1  
**Service:** Consteon VID Generator (`vid-generator`)  
**Effective Date:** 2026-08-29  

---

## 1. Classification Matrix

| Data Asset | Classification Level | Encryption at Rest | Encryption in Transit | Retention Period | Access Controls |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **14-Digit VID** | **Confidential** | AES-256 (Cloud KMS CMEK) | TLS 1.3 | Permanent | Cloud IAM (`roles/run.invoker`) + RBAC (`vid.consumer`, `vid.admin`) |
| **12-Digit Address** | **Internal** | AES-256 | TLS 1.3 | Permanent | RBAC (`vid.reader`+) |
| **Cluster & Position** | **Internal** | AES-256 | TLS 1.3 | Permanent | RBAC (`vid.reader`+) |
| **Country Code** | **Public Metadata** | AES-256 | TLS 1.3 | Permanent | Open |
| **Audit Logs** | **Restricted** | AES-256 | TLS 1.3 | **7 Years (2,555 Days)** | Read-Only: Security Officers & Admins |

---

## 2. Handling Guidelines

1. **Storage Rules:**
   - Raw VIDs and Addresses must only reside in Firestore collection `vids` under database `vid-registry`.
   - No direct hardcoded storage in external unencrypted caches.
2. **Access Control:**
   - Only authenticated backend service accounts through Cloud Run IAM invoke permissions can access the API.
3. **Disposal:**
   - Revoked VIDs are retained with status `revoked` to ensure cryptographic uniqueness and prevent accidental address reuse.
