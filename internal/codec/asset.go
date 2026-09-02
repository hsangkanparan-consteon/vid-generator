package codec

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	AssetPayloadWithoutUIDLength = 3                                                          // UNSPSC (3B) = 3 bytes
	AssetPayloadWithUIDLength    = 3 + 5                                                      // UNSPSC (3B) + AssetUID (5B) = 8 bytes
	AssetPayloadWith16ByteUIDLen = 3 + 16                                                     // UNSPSC (3B) + AssetUID (16B) = 19 bytes

	AssetTokenWithoutUIDLength   = HeaderLength + AssetPayloadWithoutUIDLength + SignatureLength // 2 + 3 + 64 = 69 bytes
	AssetTokenWithUIDLength      = HeaderLength + AssetPayloadWithUIDLength + SignatureLength    // 2 + 8 + 64 = 74 bytes
	AssetTokenWith16ByteUIDLen   = HeaderLength + AssetPayloadWith16ByteUIDLen + SignatureLength // 2 + 19 + 64 = 85 bytes
)

// AssetPayload represents the unpacked Asset QR code fields.
type AssetPayload struct {
	UNSPSC        string // UNSPSC commodity/class code (up to 6 digits, e.g. "251015" or "432115")
	HasUID        bool   // true if specific AssetUID is present; false if generic category QR
	AssetUID      uint64 // 40-bit unique asset identifier (for numeric UIDs)
	AssetIDRaw    []byte // 16-byte raw binary asset identifier (for 128-bit random IDs)
	UnencryptedID string // Scheme 0 unencrypted ID format (e.g. "0Ze3rocg-AwTnFSlxtQiRyg")
}

// EncodeUNSPSCToUint24 parses a UNSPSC code string (e.g. "251015", "4321", "2510") into a 24-bit uint32.
func EncodeUNSPSCToUint24(unspsc string) (uint32, error) {
	clean := strings.ReplaceAll(unspsc, ".", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return 0, nil
	}
	if len(clean) > 6 {
		clean = clean[:6]
	}
	val, err := strconv.ParseUint(clean, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid UNSPSC format: %w", err)
	}
	return uint32(val), nil
}

// FormatUNSPSC formats a 24-bit uint32 into a 6-digit (or 4-digit) UNSPSC string.
func FormatUNSPSC(val uint32) string {
	if val < 10000 {
		return fmt.Sprintf("%04d", val)
	}
	return fmt.Sprintf("%06d", val)
}

// EncodeAssetPayload packs AssetPayload into 3 bytes (no UID), 8 bytes (numeric 5B UID), or 19 bytes (16B UID).
func EncodeAssetPayload(p AssetPayload) ([]byte, error) {
	unspscVal, err := EncodeUNSPSCToUint24(p.UNSPSC)
	if err != nil {
		return nil, err
	}

	unspscBytes := EncodeUint24(unspscVal)

	if len(p.AssetIDRaw) == 16 {
		// 16-byte (128-bit) raw binary Asset ID: 19 bytes total
		buf := make([]byte, AssetPayloadWith16ByteUIDLen)
		copy(buf[0:3], unspscBytes[:])
		copy(buf[3:19], p.AssetIDRaw[:16])
		return buf, nil
	}

	if !p.HasUID || p.AssetUID == 0 {
		// Generic Asset: 3 bytes
		return unspscBytes[:], nil
	}

	// Specific Asset with 5-byte numeric UID: 8 bytes
	buf := make([]byte, AssetPayloadWithUIDLength)
	copy(buf[0:3], unspscBytes[:])
	uid := EncodeUint40(p.AssetUID)
	copy(buf[3:8], uid[:])

	return buf, nil
}

// DecodeAssetPayload parses 3 bytes (no UID), 8 bytes (5B numeric UID), or 19 bytes (16B UID) into AssetPayload.
func DecodeAssetPayload(b []byte) (AssetPayload, error) {
	if len(b) < AssetPayloadWithoutUIDLength {
		return AssetPayload{}, errors.New("insufficient bytes for Asset payload (minimum 3 bytes)")
	}

	unspscVal := DecodeUint24(b[0:3])
	unspscStr := FormatUNSPSC(unspscVal)

	if len(b) >= AssetPayloadWith16ByteUIDLen {
		// 16-byte (128-bit) Asset ID (19 bytes payload)
		raw16 := make([]byte, 16)
		copy(raw16, b[3:19])
		b64 := base64.RawURLEncoding.EncodeToString(raw16)
		return AssetPayload{
			UNSPSC:        unspscStr,
			HasUID:        true,
			AssetIDRaw:    raw16,
			UnencryptedID: "0" + b64,
		}, nil
	}

	if len(b) >= AssetPayloadWithUIDLength {
		// Specific Asset QR with 5-byte numeric UID (8 bytes)
		uid := DecodeUint40(b[3:8])
		return AssetPayload{
			UNSPSC:        unspscStr,
			HasUID:        true,
			AssetUID:      uid,
			UnencryptedID: fmt.Sprintf("%d", uid),
		}, nil
	}

	// Generic Category QR without UID (3 bytes)
	return AssetPayload{
		UNSPSC: unspscStr,
		HasUID: false,
	}, nil
}

// ParseAssetUIDString parses any input string into a 16-byte raw ID, a numeric UID, or generates a secure random 16-byte ID.
func ParseAssetUIDString(input string) (raw16 []byte, numUID uint64, unencryptedStr string, is16Byte bool, err error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" || strings.EqualFold(trimmed, "generate") || strings.EqualFold(trimmed, "random") || strings.EqualFold(trimmed, "auto") {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, 0, "", false, fmt.Errorf("failed to generate secure random bytes: %w", err)
		}
		b64 := base64.RawURLEncoding.EncodeToString(raw[:])
		return raw[:], 0, "0" + b64, true, nil
	}

	// Case 1: Unencrypted Scheme 0 format with '0' prefix and 22-char Base64URL (total 23 chars)
	if strings.HasPrefix(trimmed, "0") && len(trimmed) == 23 {
		b64Body := trimmed[1:]
		decoded, decErr := base64.RawURLEncoding.DecodeString(b64Body)
		if decErr == nil && len(decoded) == 16 {
			return decoded, 0, trimmed, true, nil
		}
	}

	// Case 2: Raw 22-char Base64URL string (16 bytes)
	if len(trimmed) == 22 {
		decoded, decErr := base64.RawURLEncoding.DecodeString(trimmed)
		if decErr == nil && len(decoded) == 16 {
			return decoded, 0, "0" + trimmed, true, nil
		}
	}

	// Case 3: Pure numeric integer <= 12 digits ($0 \dots 1.09 \times 10^{12}$)
	if val, numErr := strconv.ParseUint(trimmed, 10, 64); numErr == nil && val < (uint64(1)<<40) {
		return nil, val, trimmed, false, nil
	}

	// Case 4: Arbitrary semantic text (e.g. "LAPTOP-01") -> Deterministic 16-byte SHA-256 hash
	h := sha256.Sum256([]byte(trimmed))
	raw16 = h[:16]
	unenc := "0" + base64.RawURLEncoding.EncodeToString(raw16)
	return raw16, 0, unenc, true, nil
}

// CommonUNSPSCTitles provides friendly titles for standard enterprise commodity codes.
var CommonUNSPSCTitles = map[string]string{
	"432115": "Computers and laptops",
	"432116": "Computer servers",
	"432117": "Touch screens and monitors",
	"432119": "Computer peripherals",
	"431915": "Personal communication devices (Mobile Phones)",
	"451215": "Cameras and optical equipment",
	"561017": "Office furniture",
	"561015": "Chairs and seating",
	"561019": "Desks and workstations",
	"251015": "Passenger motor vehicles",
	"251016": "Commercial and transport vehicles",
	"461815": "Safety apparel and gear",
	"401017": "Air conditioners and cooling",
	"261116": "Generators and electrical power units",
	"461716": "Surveillance and security cameras",
	"461715": "Alarm and access control security systems",
}

// GetUNSPSCTitle returns the standard title for a given UNSPSC code or a generic label.
func GetUNSPSCTitle(unspsc string) string {
	if title, ok := CommonUNSPSCTitles[unspsc]; ok {
		return title
	}
	return fmt.Sprintf("Commodity (%s)", unspsc)
}
