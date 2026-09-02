#!/usr/bin/env bash
# ==============================================================================
# Script: deploy-cloud-run.sh
# Purpose: Build and deploy the Consteon QR Generator & MCP server to Google Cloud Run in Tokyo, Japan (asia-northeast1)
# Keystore: Persistent GCS Bucket (gs://authenium-prod1-qr-keystore) + Cloud KMS Envelope Encryption
# Security: IAM Protected (--no-allow-unauthenticated)
# ==============================================================================

set -euo pipefail

PROJECT_ID="authenium-prod1"
REGION="asia-northeast1"
SERVICE_NAME="consteon-qr-generator"
KMS_KEY_NAME="projects/${PROJECT_ID}/locations/${REGION}/keyRings/consteon-qr-ring/cryptoKeys/master-envelope-key"
GCS_BUCKET="authenium-prod1-qr-keystore"

echo "==> Deploying ${SERVICE_NAME} to Google Cloud Run in ${PROJECT_ID} (${REGION} - Tokyo, Japan)..."

# 1. Enable Required Google Cloud APIs
echo "==> Enabling required GCP APIs..."
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    storage.googleapis.com \
    cloudkms.googleapis.com \
    --project="${PROJECT_ID}"

# 2. Ensure GCS Keystore Bucket exists in Tokyo
if ! gcloud storage buckets describe "gs://${GCS_BUCKET}" &>/dev/null; then
    echo "==> Creating persistent GCS bucket gs://${GCS_BUCKET} in ${REGION}..."
    gcloud storage buckets create "gs://${GCS_BUCKET}" \
        --location="${REGION}" \
        --project="${PROJECT_ID}" \
        --uniform-bucket-level-access
fi

# 3. Deploy directly via Cloud Run source build
echo "==> Building and deploying Cloud Run container with GCS Keystore..."
gcloud run deploy "${SERVICE_NAME}" \
    --source="." \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --platform="managed" \
    --no-allow-unauthenticated \
    --set-env-vars="GCP_KMS_KEY_NAME=${KMS_KEY_NAME},GCS_KEYSTORE_BUCKET=${GCS_BUCKET}" \
    --min-instances=0 \
    --max-instances=10 \
    --memory="256Mi" \
    --cpu="1" \
    --timeout="30s" \
    --quiet

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --platform="managed" --region="${REGION}" --project="${PROJECT_ID}" --format="value(status.url)")

echo ""
echo "=============================================================================="
echo "✅ Cloud Run Service Deployed Successfully to Tokyo, Japan (${REGION})!"
echo "Service URL:"
echo "  ${SERVICE_URL}"
echo "Persistent Keystore:"
echo "  GCS Bucket: gs://${GCS_BUCKET}/"
echo "  KMS Key:    ${KMS_KEY_NAME}"
echo "MCP Endpoints:"
echo "  Streamable POST: ${SERVICE_URL}/mcp"
echo "  SSE Stream:      ${SERVICE_URL}/sse"
echo "IAM Protection:"
echo "  Authentication Required: YES (--no-allow-unauthenticated)"
echo "=============================================================================="
