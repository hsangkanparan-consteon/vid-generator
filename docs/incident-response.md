# Incident Response Procedures

**Standard:** ISO/IEC 27001:2022 Control 8.16 / SOC 2 CC7.3  
**Service:** Consteon VID Generator (`vid-generator`)  

---

## 1. Scenario Playbooks

### Scenario A: Duplicate Address or VID Detected
1. **Immediate Action**: Run `validate_vid` on both candidates.
2. **Investigation**: Query BigQuery audit logs:
   ```sql
   SELECT * FROM vid_audit_logs.audit_events 
   WHERE action = 'allocate_vid' AND JSON_EXTRACT_SCALAR(metadata, '$.vid') = '<target_vid>';
   ```
3. **Remediation**: Call `revoke_vid` with reason `"Collision resolution"`. Re-issue a new VID via `allocate_vid`.

### Scenario B: Cloud Run Service Unavailability / Outage
1. Check Cloud Run metrics and error rates in Google Cloud Monitoring.
2. Check Firestore health status in `authenium-prod1`.
3. If necessary, re-deploy using `gcloud run deploy vid-generator` or trigger Cloud Build pipeline.

### Scenario C: Unauthorized Access / Security Breach
1. Immediately rotate service account keys for any compromised caller.
2. Remove IAM `roles/run.invoker` role from the affected principal.
3. Review BigQuery audit trail for unauthorized allocations.
