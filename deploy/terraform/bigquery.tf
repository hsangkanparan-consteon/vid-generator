resource "google_bigquery_dataset" "vid_audit_logs" {
  project     = var.project_id
  dataset_id  = "vid_audit_logs"
  location    = var.region
  description = "7-Year Immutable Audit Archive for Consteon VID Generator (SOC 2 CC4.1 / ISO 27001 A.12.4)"

  default_partition_expiration_ms = 220752000000
  default_table_expiration_ms     = 220752000000

  access {
    role          = "OWNER"
    user_by_email = "hsangkanparan@consteon.com"
  }
}

resource "google_logging_project_sink" "vid_audit_sink" {
  project                = var.project_id
  name                   = "vid-audit-logs-to-bigquery"
  destination            = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.vid_audit_logs.dataset_id}"
  filter                 = "resource.type=\"cloud_run_revision\" AND jsonPayload.event_type=\"AUDIT_EVENT\""
  unique_writer_identity = true
}

resource "google_project_iam_member" "sink_bigquery_editor" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = google_logging_project_sink.vid_audit_sink.writer_identity
}
