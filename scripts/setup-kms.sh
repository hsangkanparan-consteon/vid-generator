#!/usr/bin/env bash
# ==============================================================================
# Script: setup-kms.sh
# Purpose: Provision Google Cloud KMS Master Envelope Encryption Key in authenium-prod1 (Tokyo, Japan)
# Cost: ~$0.06 / month
# ==============================================================================

set -euo pipefail

PROJECT_ID="authenium-prod1"
LOCATION="asia-northeast1"
KEYRING_NAME="consteon-qr-ring"
KEY_NAME="master-envelope-key"

echo "==> Configuring Google Cloud KMS for project: ${PROJECT_ID} in ${LOCATION} (Tokyo, Japan)..."

# 1. Enable Cloud KMS API
echo "==> Enabling cloudkms.googleapis.com API..."
gcloud services enable cloudkms.googleapis.com --project="${PROJECT_ID}"

# 2. Create KeyRing if it doesn't already exist
if gcloud kms keyrings describe "${KEYRING_NAME}" --location="${LOCATION}" --project="${PROJECT_ID}" &>/dev/null; then
    echo "==> KeyRing '${KEYRING_NAME}' already exists in ${LOCATION}."
else
    echo "==> Creating KeyRing '${KEYRING_NAME}' in ${LOCATION}..."
    gcloud kms keyrings create "${KEYRING_NAME}" \
        --location="${LOCATION}" \
        --project="${PROJECT_ID}"
fi

# 3. Create Master Envelope CryptoKey if it doesn't already exist
if gcloud kms keys describe "${KEY_NAME}" --keyring="${KEYRING_NAME}" --location="${LOCATION}" --project="${PROJECT_ID}" &>/dev/null; then
    echo "==> CryptoKey '${KEY_NAME}' already exists."
else
    echo "==> Creating CryptoKey '${KEY_NAME}' (purpose=encryption, protection-level=software)..."
    gcloud kms keys create "${KEY_NAME}" \
        --keyring="${KEYRING_NAME}" \
        --location="${LOCATION}" \
        --purpose="encryption" \
        --protection-level="software" \
        --project="${PROJECT_ID}"
fi

FULL_KEY_NAME="projects/${PROJECT_ID}/locations/${LOCATION}/keyRings/${KEYRING_NAME}/cryptoKeys/${KEY_NAME}"

echo ""
echo "=============================================================================="
echo "✅ Google Cloud KMS Master Key Successfully Configured!"
echo "Full Resource Name:"
echo "  ${FULL_KEY_NAME}"
echo "=============================================================================="
