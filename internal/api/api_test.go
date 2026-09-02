package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"consteon.com/qr-generator/internal/keystore"
	"consteon.com/qr-generator/internal/kms"
	"consteon.com/qr-generator/internal/mcp"
	"consteon.com/qr-generator/pkg/verifier"
)

func setupTestServer(t *testing.T) (*http.ServeMux, keystore.Keystore, *kms.MockKMSClient) {
	os.Setenv("ALLOW_LOCAL_DEV", "true")
	mockKMS, err := kms.NewMockKMSClient()
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	store := keystore.NewEncryptedKeystore(mockKMS)
	h := NewHandler(store)
	mcpServer := mcp.NewServer(store)
	mcpHandler := mcp.NewHTTPHandler(mcpServer)

	mux := http.NewServeMux()
	RegisterRoutes(mux, h, mcpHandler, "")

	return mux, store, mockKMS
}

func TestEndToEndMintAndVerify(t *testing.T) {
	mux, store, _ := setupTestServer(t)
	ctx := context.Background()

	tenantID := "10002000300040"
	keyVer := uint8(1)

	// 1. Pre-generate tenant key
	keyRec, err := store.GenerateTenantKey(ctx, tenantID, keyVer)
	if err != nil {
		t.Fatalf("failed to generate tenant key: %v", err)
	}

	// 2. Setup Offline Verifier
	v := verifier.NewOfflineVerifier()
	v.AddTenantKey(keyVer, keyRec.PublicKey)

	// --- TEST 1: Mint Location QR ---
	t.Run("Mint Location QR", func(t *testing.T) {
		locReq := MintLocationRequest{
			TenantID:    tenantID,
			CountryCode: 360,
			Subtype:     "gate",
			LocationUID: 123456789,
		}
		body, _ := json.Marshal(locReq)
		req := httptest.NewRequest("POST", "/v1/qr/location", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer dev-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp MintResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Verify Token Offline using Verifier SDK
		res, err := v.VerifyURL(resp.FullURL)
		if err != nil {
			t.Fatalf("offline verification failed for Location URL: %v", err)
		}

		if res.Location == nil {
			t.Fatal("expected location payload, got nil")
		}
		if res.Location.CountryCode != 360 {
			t.Errorf("expected country 360, got %d", res.Location.CountryCode)
		}
		if res.Location.LocationUID != 123456789 || !res.Location.HasUID {
			t.Errorf("expected UID 123456789, got %d (has_uid=%v)", res.Location.LocationUID, res.Location.HasUID)
		}
	})

	// --- TEST 2: Mint Asset QR with UNSPSC & UID ---
	t.Run("Mint Asset QR with UID", func(t *testing.T) {
		assetReq := MintAssetRequest{
			TenantID: tenantID,
			UNSPSC:   "251015",
			AssetUID: "CAR-99281",
		}
		body, _ := json.Marshal(assetReq)
		req := httptest.NewRequest("POST", "/v1/qr/asset", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer dev-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp MintResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Verify Token Offline
		res, err := v.VerifyURL(resp.FullURL)
		if err != nil {
			t.Fatalf("offline verification failed for Asset URL: %v", err)
		}

		if res.Asset == nil {
			t.Fatal("expected asset payload, got nil")
		}
		if res.Asset.UNSPSC != "251015" {
			t.Errorf("expected UNSPSC 251015, got %s", res.Asset.UNSPSC)
		}
		if !res.Asset.HasUID || (res.Asset.AssetUID == 0 && len(res.Asset.AssetIDRaw) == 0) {
			t.Errorf("expected valid Asset UID or Raw ID, got UID=%d rawLen=%d (has_uid=%v)", res.Asset.AssetUID, len(res.Asset.AssetIDRaw), res.Asset.HasUID)
		}
	})

	// --- TEST 3: Mint Generic Asset QR (without UID -> 69B) ---
	t.Run("Mint Generic Asset QR without UID", func(t *testing.T) {
		assetReq := MintAssetRequest{
			TenantID: tenantID,
			UNSPSC:   "432115",
		}
		body, _ := json.Marshal(assetReq)
		req := httptest.NewRequest("POST", "/v1/qr/asset", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer dev-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp MintResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.RawBytesCount != 69 {
			t.Errorf("expected 69 bytes for asset without UID, got %d", resp.RawBytesCount)
		}

		// Verify Token Offline
		res, err := v.VerifyURL(resp.FullURL)
		if err != nil {
			t.Fatalf("offline verification failed for Generic Asset URL: %v", err)
		}

		if res.Asset == nil {
			t.Fatal("expected asset payload, got nil")
		}
		if res.Asset.UNSPSC != "432115" {
			t.Errorf("expected UNSPSC 432115, got %s", res.Asset.UNSPSC)
		}
		if res.Asset.HasUID {
			t.Errorf("expected HasUID=false, got true")
		}
	})

	// --- TEST 4: Mint User VID QR ---
	t.Run("Mint User VID QR", func(t *testing.T) {
		userReq := MintUserRequest{
			TenantID: tenantID,
			VID:      "12345678901234",
		}
		body, _ := json.Marshal(userReq)
		req := httptest.NewRequest("POST", "/v1/qr/user", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer dev-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp MintResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Verify Token Offline
		res, err := v.VerifyURL(resp.FullURL)
		if err != nil {
			t.Fatalf("offline verification failed for User URL: %v", err)
		}

		if res.User == nil {
			t.Fatal("expected user payload, got nil")
		}
		if res.User.VID != "12345678901234" {
			t.Errorf("expected VID 12345678901234, got %s", res.User.VID)
		}
	})

	// --- TEST 5: Mint 16-Byte Location QR and Decode via /v1/qr/decode ---
	t.Run("Mint and Decode 16-Byte Location QR", func(t *testing.T) {
		locReq := MintLocationRequest{
			TenantID:    tenantID,
			CountryCode: 62,
			Subtype:     "gate",
			LocationUID: "0Ze3rocg-AwTnFSlxtQiRyg", // 23-char unencrypted ID
		}
		body, _ := json.Marshal(locReq)
		req := httptest.NewRequest("POST", "/v1/qr/location", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer dev-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var mintResp MintResponse
		if err := json.NewDecoder(rec.Body).Decode(&mintResp); err != nil {
			t.Fatalf("failed to decode mint response: %v", err)
		}

		if mintResp.RawBytesCount != 85 {
			t.Errorf("expected 85 bytes for 16-byte location QR, got %d", mintResp.RawBytesCount)
		}

		if mintResp.UnencryptedID != "0Ze3rocg-AwTnFSlxtQiRyg" {
			t.Errorf("expected unencrypted ID '0Ze3rocg-AwTnFSlxtQiRyg', got '%s'", mintResp.UnencryptedID)
		}

		// Call /v1/qr/decode endpoint
		decodeReq := DecodeQRRequest{
			Token:    mintResp.TokenBase64URL,
			TenantID: tenantID,
		}
		decBody, _ := json.Marshal(decodeReq)
		decHTTPReq := httptest.NewRequest("POST", "/v1/qr/decode", bytes.NewReader(decBody))
		decHTTPReq.Header.Set("Authorization", "Bearer dev-token")
		decHTTPReq.Header.Set("Content-Type", "application/json")
		decRec := httptest.NewRecorder()

		mux.ServeHTTP(decRec, decHTTPReq)

		if decRec.Code != http.StatusOK {
			t.Fatalf("expected decode status 200, got %d: %s", decRec.Code, decRec.Body.String())
		}

		var decResp DecodeQRResponse
		if err := json.NewDecoder(decRec.Body).Decode(&decResp); err != nil {
			t.Fatalf("failed to decode DecodeQR response: %v", err)
		}

		if !decResp.IsValid {
			t.Errorf("expected valid signature, got error: %s", decResp.Error)
		}
		if decResp.Type != "location" {
			t.Errorf("expected type 'location', got '%s'", decResp.Type)
		}
		if decResp.Subtype != "gate" {
			t.Errorf("expected subtype 'gate', got '%s'", decResp.Subtype)
		}
		if decResp.LocationID != "0Ze3rocg-AwTnFSlxtQiRyg" {
			t.Errorf("expected location_id '0Ze3rocg-AwTnFSlxtQiRyg', got '%s'", decResp.LocationID)
		}
		if !decResp.IsRegistered {
			t.Errorf("expected is_registered=true, got false")
		}
	})

	// --- TEST 6: Zero Redundancy Rejection (409 Conflict) ---
	t.Run("Reject Duplicate Location and Asset IDs", func(t *testing.T) {
		// 1. First Mint should succeed
		locReq := MintLocationRequest{
			TenantID:    tenantID,
			CountryCode: 62,
			Subtype:     "room",
			LocationUID: "0Room101UniqueAlphaBeta",
		}
		body, _ := json.Marshal(locReq)
		req := httptest.NewRequest("POST", "/v1/qr/location", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer dev-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("first mint expected 200, got %d", rec.Code)
		}

		// 2. Second Mint with same Location ID MUST fail with 409 Conflict
		req2 := httptest.NewRequest("POST", "/v1/qr/location", bytes.NewReader(body))
		req2.Header.Set("Authorization", "Bearer dev-token")
		req2.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		mux.ServeHTTP(rec2, req2)

		if rec2.Code != http.StatusConflict {
			t.Fatalf("duplicate location mint expected 409 Conflict, got %d: %s", rec2.Code, rec2.Body.String())
		}

		// 3. Asset duplicate test
		assetReq := MintAssetRequest{
			TenantID: tenantID,
			UNSPSC:   "432115",
			AssetUID: "0LaptopDellLatitude2026",
		}
		aBody, _ := json.Marshal(assetReq)
		aReq1 := httptest.NewRequest("POST", "/v1/qr/asset", bytes.NewReader(aBody))
		aReq1.Header.Set("Authorization", "Bearer dev-token")
		aReq1.Header.Set("Content-Type", "application/json")
		aRec1 := httptest.NewRecorder()
		mux.ServeHTTP(aRec1, aReq1)

		if aRec1.Code != http.StatusOK {
			t.Fatalf("first asset mint expected 200, got %d", aRec1.Code)
		}

		// Second Asset Mint with same ID MUST fail with 409 Conflict
		aReq2 := httptest.NewRequest("POST", "/v1/qr/asset", bytes.NewReader(aBody))
		aReq2.Header.Set("Authorization", "Bearer dev-token")
		aReq2.Header.Set("Content-Type", "application/json")
		aRec2 := httptest.NewRecorder()
		mux.ServeHTTP(aRec2, aReq2)

		if aRec2.Code != http.StatusConflict {
			t.Fatalf("duplicate asset mint expected 409 Conflict, got %d: %s", aRec2.Code, aRec2.Body.String())
		}
	})
}
