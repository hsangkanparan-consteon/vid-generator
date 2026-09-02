/**
 * Google Apps Script for Consteon QR Generator (Deployed in Tokyo, Japan)
 * 
 * Instructions:
 * 1. Open your Google Spreadsheet
 * 2. Extensions -> Apps Script
 * 3. Paste this code into Code.gs
 */

const CLOUD_RUN_URL = "https://consteon-qr-generator-mtabakupaq-an.a.run.app";

/**
 * Custom Google Sheets formula to mint a Location QR.
 * Usage: =MINT_LOCATION_QR("10002000300040", 360, "gate", 123456)
 * 
 * @param {string} tenantId 14-digit numeric tenant ID (e.g. "10002000300040" or "00000000000000" for Global)
 * @param {number} countryCode ISO 3166-1 country code (e.g. 360)
 * @param {string} subtype "portal", "guard_station", "room", "toilet", "gate", "checkpoint"
 * @param {any} locationUid Optional unique location ID number or name
 * @return {string} Token string starting with '3' (or full URL)
 * @customfunction
 */
function MINT_LOCATION_QR(tenantId, countryCode, subtype, locationUid) {
  const payload = {
    tenant_id: String(tenantId || "00000000000000"),
    country_code: Number(countryCode || 360),
    subtype: String(subtype || "gate")
  };
  if (locationUid) {
    payload.location_uid = locationUid;
  }

  return callCloudRunService("/v1/qr/location", payload);
}

/**
 * Custom Google Sheets formula to mint an Asset QR with UNSPSC.
 * Usage: =MINT_ASSET_QR("10002000300040", "251015", "CAR-99281")
 * 
 * @param {string} tenantId 14-digit numeric tenant ID
 * @param {string} unspsc 4-digit or 6-digit UNSPSC code (e.g. "251015" for passenger cars, "432115" for computers)
 * @param {any} assetUid Optional Asset UID, serial number, or omitted for generic category QR
 * @return {string} Token string starting with '3' (or full URL)
 * @customfunction
 */
function MINT_ASSET_QR(tenantId, unspsc, assetUid) {
  const payload = {
    tenant_id: String(tenantId),
    unspsc: String(unspsc || "251015")
  };
  if (assetUid) {
    payload.asset_uid = assetUid;
  }

  return callCloudRunService("/v1/qr/asset", payload);
}

/**
 * Custom Google Sheets formula to mint a User VID QR.
 * Usage: =MINT_USER_QR("10002000300040", "12345678901234")
 * 
 * @param {string} tenantId 14-digit numeric tenant ID
 * @param {string} vid 14-digit numeric VID
 * @return {string} Token string starting with '3' (or full URL)
 * @customfunction
 */
function MINT_USER_QR(tenantId, vid) {
  const payload = {
    tenant_id: String(tenantId),
    vid: String(vid)
  };

  return callCloudRunService("/v1/qr/user", payload);
}

/**
 * Helper to execute authenticated HTTP POST to Cloud Run service using Google IAM Identity Token.
 */
function callCloudRunService(endpoint, body) {
  try {
    const url = CLOUD_RUN_URL + endpoint;
    const idToken = ScriptApp.getIdentityToken();

    const options = {
      method: "post",
      contentType: "application/json",
      headers: {
        "Authorization": "Bearer " + idToken
      },
      payload: JSON.stringify(body),
      muteHttpExceptions: true
    };

    const response = UrlFetchApp.fetch(url, options);
    const code = response.getResponseCode();

    if (code !== 200) {
      return "ERROR (" + code + "): " + response.getContentText();
    }

    const data = JSON.parse(response.getContentText());
    return data.token_base64url; // Returns token string starting with '3' for cell A2
  } catch (err) {
    return "ERROR: " + err.message;
  }
}
