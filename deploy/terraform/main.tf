terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  type        = string
  default     = "authenium-prod1"
  description = "GCP Project ID"
}

variable "region" {
  type        = string
  default     = "asia-southeast1"
  description = "GCP Region for Cloud Run and Firestore"
}

variable "service_name" {
  type        = string
  default     = "vid-generator"
  description = "Cloud Run service name"
}

resource "google_service_account" "vid_generator_sa" {
  account_id   = "vid-generator-sa"
  display_name = "VID Generator Cloud Run Service Account"
}

resource "google_project_iam_member" "firestore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.vid_generator_sa.email}"
}

resource "google_project_iam_member" "log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vid_generator_sa.email}"
}

resource "google_cloud_run_v2_service" "vid_generator" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.vid_generator_sa.email

    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }

    containers {
      image = "gcr.io/${var.project_id}/${var.service_name}:latest"

      resources {
        limits = {
          cpu    = "1000m"
          memory = "256Mi"
        }
      }

      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "DATABASE_ID"
        value = "vid-registry"
      }
      env {
        name  = "ENVIRONMENT"
        value = "production"
      }
    }
  }

  depends_on = [
    google_firestore_database.vid_registry
  ]
}
