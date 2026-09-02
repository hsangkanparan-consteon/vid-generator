package verifier

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"consteon.com/qr-generator/internal/codec"
	"consteon.com/qr-generator/internal/crypto"
	"consteon.com/qr-generator/pkg/sheets"
)

var (
	ErrTokenTooShort        = errors.New("token length is insufficient (minimum 66 bytes: 2B header + 64B signature)")
	ErrSignatureFailed      = errors.New("signature verification failed: invalid or counterfeit QR code")
	ErrUntrustedIssuer      = errors.New("signature could not be verified with tenant or global public keys")
	ErrUnsupportedURLFormat = errors.New("URL does not start with expected prefix https://autsorz/l/")
	ErrLegacyScheme         = errors.New("legacy or unsupported encryption scheme (expected scheme 3)")
)

// VerifiedResult holds the successfully verified and unpacked QR token data.
type VerifiedResult struct {
	Scheme           string                 `json:"scheme"`
	Type             codec.QRType           `json:"type"`
	TypeName         string                 `json:"type_name"`
	FormatVersion    uint8                  `json:"format_version"`
	KeyVersion       uint8                  `json:"key_version"`
	IsGlobalFacility bool                   `json:"is_global_facility"`
	Location         *codec.LocationPayload `json:"location,omitempty"`
	Asset            *codec.AssetPayload    `json:"asset,omitempty"`
	User             *codec.UserPayload     `json:"user,omitempty"`
	Other            *codec.OtherPayload    `json:"other,omitempty"`
}

// OfflineVerifier manages trusted public keys and executes offline cryptographic verification.
type OfflineVerifier struct {
	tenantKeys        map[uint8]ed25519.PublicKey // keyVer -> PublicKey
	globalFacilityKey ed25519.PublicKey          // Optional fallback for shared buildings/gates
}

// NewOfflineVerifier creates an offline verifier.
func NewOfflineVerifier() *OfflineVerifier {
	return &OfflineVerifier{
		tenantKeys: make(map[uint8]ed25519.PublicKey),
	}
}

// AddTenantKey registers a tenant public key for a specific key version.
func (v *OfflineVerifier) AddTenantKey(keyVer uint8, pubKey ed25519.PublicKey) {
	v.tenantKeys[keyVer] = pubKey
}

// SetGlobalFacilityKey registers the shared/global facility public key.
func (v *OfflineVerifier) SetGlobalFacilityKey(pubKey ed25519.PublicKey) {
	v.globalFacilityKey = pubKey
}

// VerifyURL parses a full URL like "https://autsorz/l/3<Base64URL>" and verifies it offline.
func (v *OfflineVerifier) VerifyURL(rawURL string) (*VerifiedResult, error) {
	trimmed := strings.TrimSpace(rawURL)
	if !strings.HasPrefix(trimmed, sheets.DefaultBaseURL) {
		// If someone passed raw token string directly (e.g. "3AQEB...")
		if !strings.Contains(trimmed, "://") {
			return v.VerifyBase64URL(trimmed)
		}
		return nil, ErrUnsupportedURLFormat
	}

	tokenWithScheme := strings.TrimPrefix(trimmed, sheets.DefaultBaseURL)
	return v.VerifyBase64URL(tokenWithScheme)
}

// VerifyBase64URL inspects the scheme prefix ('3'), decodes Base64URL string, and executes verification.
func (v *OfflineVerifier) VerifyBase64URL(tokenStr string) (*VerifiedResult, error) {
	clean := strings.TrimSpace(tokenStr)
	if clean == "" {
		return nil, errors.New("empty token string")
	}

	scheme := ""
	base64Data := clean

	// Check scheme prefix (0 = no enc, 1/2 = legacy enc, 3 = Ed25519 Asymmetric)
	firstChar := clean[0]
	if firstChar == '3' {
		scheme = "3"
		base64Data = clean[1:]
	} else if firstChar == '0' || firstChar == '1' || firstChar == '2' {
		return nil, fmt.Errorf("%w: scheme '%c'", ErrLegacyScheme, firstChar)
	}

	tokenBytes, err := crypto.DecodeBase64URL(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base64URL token: %w", err)
	}

	res, err := v.VerifyRawToken(tokenBytes)
	if err != nil {
		return nil, err
	}

	if scheme != "" {
		res.Scheme = scheme
	} else {
		res.Scheme = "3"
	}

	return res, nil
}

// VerifyRawToken verifies the raw byte token offline.
func (v *OfflineVerifier) VerifyRawToken(tokenBytes []byte) (*VerifiedResult, error) {
	minLen := codec.HeaderLength + codec.SignatureLength // 2 + 64 = 66
	if len(tokenBytes) < minLen {
		return nil, ErrTokenTooShort
	}

	// 1. Split into Message and 64-byte Signature
	msgLen := len(tokenBytes) - codec.SignatureLength
	message := tokenBytes[:msgLen]
	signature := tokenBytes[msgLen:]

	// 2. Decode 2-byte header
	header, err := codec.DecodeHeader(message[:codec.HeaderLength])
	if err != nil {
		return nil, fmt.Errorf("malformed token header: %w", err)
	}

	// 3. Cryptographic Verification: Try Tenant Key for this KeyVersion
	verified := false
	isGlobal := false

	if tenantPub, exists := v.tenantKeys[header.KeyVersion]; exists {
		if crypto.Verify(tenantPub, message, signature) {
			verified = true
		}
	}

	// Fall back to Global Facility Key if not verified
	if !verified && len(v.globalFacilityKey) == ed25519.PublicKeySize {
		if crypto.Verify(v.globalFacilityKey, message, signature) {
			verified = true
			isGlobal = true
		}
	}

	if !verified {
		return nil, ErrUntrustedIssuer
	}

	// 4. Unpack payload according to Type
	payloadBytes := message[codec.HeaderLength:]
	result := &VerifiedResult{
		Scheme:           "3",
		Type:             header.Type,
		TypeName:         "",
		FormatVersion:    header.FormatVersion,
		KeyVersion:       header.KeyVersion,
		IsGlobalFacility: isGlobal,
	}

	switch header.Type {
	case codec.TypeLocation:
		result.TypeName = "location"
		loc, err := codec.DecodeLocationPayload(payloadBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Location payload: %w", err)
		}
		result.Location = &loc

	case codec.TypeAsset:
		result.TypeName = "asset"
		ast, err := codec.DecodeAssetPayload(payloadBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Asset payload: %w", err)
		}
		result.Asset = &ast

	case codec.TypeUser:
		result.TypeName = "user"
		usr, err := codec.DecodeUserPayload(payloadBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decode User payload: %w", err)
		}
		result.User = &usr

	case codec.TypeOther:
		result.TypeName = "other"
		oth, err := codec.DecodeOtherPayload(payloadBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Other payload: %w", err)
		}
		result.Other = &oth

	default:
		return nil, fmt.Errorf("unknown QR type: %d", header.Type)
	}

	return result, nil
}
