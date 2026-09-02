package verifier

import (
	"testing"

	"consteon.com/qr-generator/internal/codec"
	"consteon.com/qr-generator/internal/crypto"
	"consteon.com/qr-generator/pkg/sheets"
)

func TestVerifierMultiKeyAndFallback(t *testing.T) {
	// Generate Tenant Key
	tenantPub, tenantPriv, _ := crypto.GenerateKeyPair()
	// Generate Global Facility Key
	globalPub, globalPriv, _ := crypto.GenerateKeyPair()
	// Generate Rogue/Attacker Key
	_, roguePriv, _ := crypto.GenerateKeyPair()

	v := NewOfflineVerifier()
	v.AddTenantKey(1, tenantPub)
	v.SetGlobalFacilityKey(globalPub)

	header := codec.EncodeHeader(codec.Header{
		Type:          codec.TypeLocation,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    1,
	})

	locPayload := codec.EncodeLocationPayload(codec.LocationPayload{
		CountryCode: 360,
		Subtype:     codec.LocSubtypeGate,
		HasUID:      true,
		LocationUID: 123456,
	})

	message := append(header[:], locPayload...)

	// 1. Token signed by Tenant Key
	tenantSig, _ := crypto.Sign(tenantPriv, message)
	tenantToken := append(message, tenantSig...)
	tenantURL := sheets.BuildFullURL(crypto.EncodeBase64URL(tenantToken))

	res, err := v.VerifyURL(tenantURL)
	if err != nil {
		t.Fatalf("failed to verify tenant token: %v", err)
	}
	if res.IsGlobalFacility {
		t.Error("expected IsGlobalFacility=false for tenant token")
	}
	if res.Location.LocationUID != 123456 || !res.Location.HasUID {
		t.Errorf("expected UID 123456 (has_uid=true), got %d (has_uid=%v)", res.Location.LocationUID, res.Location.HasUID)
	}

	// 2. Token signed by Global Facility Key
	globalSig, _ := crypto.Sign(globalPriv, message)
	globalToken := append(message, globalSig...)
	globalURL := sheets.BuildFullURL(crypto.EncodeBase64URL(globalToken))

	resGlobal, err := v.VerifyURL(globalURL)
	if err != nil {
		t.Fatalf("failed to verify global token: %v", err)
	}
	if !resGlobal.IsGlobalFacility {
		t.Error("expected IsGlobalFacility=true for global facility token")
	}

	// 3. Token signed by Rogue/Attacker Key -> MUST FAIL
	rogueSig, _ := crypto.Sign(roguePriv, message)
	rogueToken := append(message, rogueSig...)
	rogueURL := sheets.BuildFullURL(crypto.EncodeBase64URL(rogueToken))

	_, err = v.VerifyURL(rogueURL)
	if err == nil {
		t.Error("expected error verifying rogue token, got nil")
	}
}

func TestVerifierAssetPayload(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	v := NewOfflineVerifier()
	v.AddTenantKey(1, pub)

	// Test 1: Asset With UID (74 bytes)
	header := codec.EncodeHeader(codec.Header{
		Type:          codec.TypeAsset,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    1,
	})

	assetPayload, _ := codec.EncodeAssetPayload(codec.AssetPayload{
		UNSPSC:   "251015",
		HasUID:   true,
		AssetUID: 987654,
	})

	message := append(header[:], assetPayload...)
	sig, _ := crypto.Sign(priv, message)
	token := append(message, sig...)

	tokenURL := sheets.BuildFullURL(crypto.EncodeBase64URL(token))
	res, err := v.VerifyURL(tokenURL)
	if err != nil {
		t.Fatalf("failed to verify asset URL: %v", err)
	}

	if res.Asset.UNSPSC != "251015" {
		t.Errorf("expected UNSPSC 251015, got %s", res.Asset.UNSPSC)
	}
	if res.Asset.AssetUID != 987654 || !res.Asset.HasUID {
		t.Errorf("expected Asset UID 987654 (has_uid=true), got %d (has_uid=%v)", res.Asset.AssetUID, res.Asset.HasUID)
	}

	// Test 2: Generic Asset Without UID (69 bytes)
	assetPayloadNoUID, _ := codec.EncodeAssetPayload(codec.AssetPayload{
		UNSPSC: "432115",
		HasUID: false,
	})

	msgNoUID := append(header[:], assetPayloadNoUID...)
	sigNoUID, _ := crypto.Sign(priv, msgNoUID)
	tokenNoUID := append(msgNoUID, sigNoUID...)

	if len(tokenNoUID) != 69 {
		t.Fatalf("expected 69 bytes, got %d", len(tokenNoUID))
	}

	resNoUID, err := v.VerifyURL(sheets.BuildFullURL(crypto.EncodeBase64URL(tokenNoUID)))
	if err != nil {
		t.Fatalf("failed to verify generic asset URL: %v", err)
	}

	if resNoUID.Asset.UNSPSC != "432115" || resNoUID.Asset.HasUID {
		t.Errorf("mismatch for generic asset: got %+v", resNoUID.Asset)
	}
}
