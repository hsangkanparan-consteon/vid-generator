# Backup & Disaster Recovery Plan

**Standard:** ISO/IEC 27001:2022 Control 8.13 / SOC 2 A1.2  
**Service:** Consteon VID Generator (`vid-generator`)  

---

## 1. Objectives
* **Recovery Point Objective (RPO):** $< 1 \text{ Hour}$
* **Recovery Time Objective (RTO):** $< 4 \text{ Hours}$

---

## 2. Backup Mechanisms

1. **Continuous Point-In-Time Recovery (PITR):**
   - Enabled on Firestore database `vid-registry`.
   - Allows restoring the database to any exact second within the past 7 days.
2. **Scheduled Database Backups:**
   - Daily automated exports stored in Google Cloud Storage (`gs://authenium-vid-backups/`).
   - Bucket lifecycle rule automatically retains daily backups for 90 days.

---

## 3. Disaster Recovery Procedure

To restore the `vid-registry` database to a previous timestamp:
```bash
gcloud firestore databases restore \
  --project="authenium-prod1" \
  --source-database="vid-registry" \
  --destination-database="vid-registry-restored" \
  --recovery-time="2026-08-29T10:00:00Z"
```
