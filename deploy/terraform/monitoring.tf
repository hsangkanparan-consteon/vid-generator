resource "google_monitoring_alert_policy" "low_stock_alert" {
  project      = var.project_id
  display_name = "VID Generator - Low Stock Warning (< 5,000 available)"
  combiner     = "OR"

  conditions {
    display_name = "Available stock below threshold"

    condition_matched_log {
      filter = "resource.type=\"cloud_run_revision\" AND jsonPayload.remaining_available_stock < 5000"
    }
  }

  documentation {
    content   = "Available VID stock for one or more countries has fallen below 5,000. Please run the `generate_stock` tool to replenish."
    mime_type = "text/markdown"
  }
}

resource "google_monitoring_alert_policy" "high_error_rate" {
  project      = var.project_id
  display_name = "VID Generator - High Error Rate (> 1%)"
  combiner     = "OR"

  conditions {
    display_name = "HTTP 5xx error rate"

    condition_threshold {
      filter          = "metric.type=\"run.googleapis.com/request_count\" AND resource.type=\"cloud_run_revision\" AND metric.labels.response_code_class=\"5xx\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.01

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
}
