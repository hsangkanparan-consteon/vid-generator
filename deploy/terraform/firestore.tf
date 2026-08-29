resource "google_firestore_database" "vid_registry" {
  project                     = var.project_id
  name                        = "vid-registry"
  location_id                 = var.region
  type                        = "FIRESTORE_NATIVE"
  concurrency_mode            = "OPTIMISTIC"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  delete_protection_state     = "DELETE_PROTECTION_ENABLED"
}

resource "google_firestore_index" "idx_country_status" {
  project    = var.project_id
  database   = google_firestore_database.vid_registry.name
  collection = "vids"

  fields {
    field_path = "country"
    order      = "ASCENDING"
  }

  fields {
    field_path = "status"
    order      = "ASCENDING"
  }
}
