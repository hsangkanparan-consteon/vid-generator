package codec

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type LocationSubtype uint8

const (
	LocSubtypePortal       LocationSubtype = 1
	LocSubtypeGuardStation LocationSubtype = 2
	LocSubtypeRoom         LocationSubtype = 3
	LocSubtypeToilet       LocationSubtype = 4
	LocSubtypeGate         LocationSubtype = 5
	LocSubtypeCheckpoint   LocationSubtype = 6
	LocSubtypeOther        LocationSubtype = 255

	LocationPayloadWithoutUIDLength = 2 + 1                                                             // Country (2B) + Subtype (1B) = 3 bytes
	LocationPayloadWithUIDLength    = 2 + 1 + 5                                                         // Country (2B) + Subtype (1B) + LocationUID (5B) = 8 bytes
	LocationPayloadWith16ByteUIDLen = 2 + 1 + 16                                                        // Country (2B) + Subtype (1B) + LocationUID (16B) = 19 bytes

	LocationTokenWithoutUIDLength   = HeaderLength + LocationPayloadWithoutUIDLength + SignatureLength // 2 + 3 + 64 = 69 bytes
	LocationTokenWithUIDLength      = HeaderLength + LocationPayloadWithUIDLength + SignatureLength    // 2 + 8 + 64 = 74 bytes
	LocationTokenWith16ByteUIDLen   = HeaderLength + LocationPayloadWith16ByteUIDLen + SignatureLength // 2 + 19 + 64 = 85 bytes
)

// LocationPayload represents the unpacked Location QR code fields.
type LocationPayload struct {
	CountryCode   uint16          // ISO 3166-1 numeric (e.g. 360)
	Subtype       LocationSubtype // Portal, Guard Station, Gate, Room, etc.
	HasUID        bool            // true if specific LocationUID is present; false if generic location
	LocationUID   uint64          // 40-bit unique location identifier (for numeric UIDs)
	LocationIDRaw []byte          // 16-byte raw binary location identifier (for 128-bit random IDs)
	UnencryptedID string          // Scheme 0 unencrypted ID format (e.g. "0Ze3rocg-AwTnFSlxtQiRyg")
}

// EncodeLocationPayload packs LocationPayload into 3 bytes (no UID), 8 bytes (numeric 5B UID), or 19 bytes (16B UID).
func EncodeLocationPayload(p LocationPayload) []byte {
	if len(p.LocationIDRaw) == 16 {
		// 16-byte (128-bit) raw binary Location ID: 19 bytes total
		var buf [LocationPayloadWith16ByteUIDLen]byte
		binary.BigEndian.PutUint16(buf[0:2], p.CountryCode)
		buf[2] = byte(p.Subtype)
		copy(buf[3:19], p.LocationIDRaw[:16])
		return buf[:]
	}

	if !p.HasUID || p.LocationUID == 0 {
		// Generic Location without UID: 3 bytes
		var buf [LocationPayloadWithoutUIDLength]byte
		binary.BigEndian.PutUint16(buf[0:2], p.CountryCode)
		buf[2] = byte(p.Subtype)
		return buf[:]
	}

	// Specific Location with 5-byte numeric UID: 8 bytes
	var buf [LocationPayloadWithUIDLength]byte
	binary.BigEndian.PutUint16(buf[0:2], p.CountryCode)
	buf[2] = byte(p.Subtype)
	uid := EncodeUint40(p.LocationUID)
	copy(buf[3:8], uid[:])

	return buf[:]
}

// DecodeLocationPayload parses 3 bytes (no UID), 8 bytes (5B numeric UID), or 19 bytes (16B UID) into LocationPayload.
func DecodeLocationPayload(b []byte) (LocationPayload, error) {
	if len(b) < LocationPayloadWithoutUIDLength {
		return LocationPayload{}, errors.New("insufficient bytes for Location payload (need at least 3 bytes)")
	}

	country := binary.BigEndian.Uint16(b[0:2])
	subtype := LocationSubtype(b[2])

	if len(b) >= LocationPayloadWith16ByteUIDLen {
		// 16-byte (128-bit) Location ID (19 bytes payload)
		raw16 := make([]byte, 16)
		copy(raw16, b[3:19])
		b64 := base64.RawURLEncoding.EncodeToString(raw16)
		return LocationPayload{
			CountryCode:   country,
			Subtype:       subtype,
			HasUID:        true,
			LocationIDRaw: raw16,
			UnencryptedID: "0" + b64,
		}, nil
	}

	if len(b) >= LocationPayloadWithUIDLength {
		// Specific Location with 5-byte numeric UID (8 bytes)
		uid := DecodeUint40(b[3:8])
		return LocationPayload{
			CountryCode:   country,
			Subtype:       subtype,
			HasUID:        true,
			LocationUID:   uid,
			UnencryptedID: fmt.Sprintf("%d", uid),
		}, nil
	}

	// Generic Location without UID (3 bytes)
	return LocationPayload{
		CountryCode: country,
		Subtype:     subtype,
		HasUID:      false,
	}, nil
}

// ParseLocationSubtype parses a string label into a LocationSubtype.
func ParseLocationSubtype(s string) LocationSubtype {
	switch s {
	case "0", "unknown", "unspecified":
		return 0
	case "portal", "entrance", "1":
		return LocSubtypePortal
	case "guard_station", "guard", "pos_satpam", "2":
		return LocSubtypeGuardStation
	case "room", "office", "3":
		return LocSubtypeRoom
	case "toilet", "restroom", "4":
		return LocSubtypeToilet
	case "gate", "turnstile", "portal_gate", "5":
		return LocSubtypeGate
	case "checkpoint", "patrol_point", "6":
		return LocSubtypeCheckpoint
	default:
		if v, err := strconv.ParseUint(s, 10, 8); err == nil {
			return LocationSubtype(v)
		}
		return LocSubtypeOther
	}
}

func (s LocationSubtype) String() string {
	switch s {
	case 0:
		return "unknown"
	case LocSubtypePortal:
		return "portal"
	case LocSubtypeGuardStation:
		return "guard_station"
	case LocSubtypeRoom:
		return "room"
	case LocSubtypeToilet:
		return "toilet"
	case LocSubtypeGate:
		return "gate"
	case LocSubtypeCheckpoint:
		return "checkpoint"
	default:
		return fmt.Sprintf("%d", s)
	}
}

// GenerateSecureRandom16 generates 16 cryptographically secure random bytes (128 bits of entropy)
// and returns both the raw 16 bytes and the Scheme 0 unencrypted ID (with '0' prefix).
func GenerateSecureRandom16() (rawBytes [16]byte, unencryptedID string, err error) {
	if _, err := rand.Read(rawBytes[:]); err != nil {
		return [16]byte{}, "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(rawBytes[:])
	return rawBytes, "0" + b64, nil
}

// ParseLocationUIDString parses any input string into a 16-byte raw ID, a numeric UID, or generates a secure random 16-byte ID.
func ParseLocationUIDString(input string) (raw16 []byte, numUID uint64, unencryptedStr string, is16Byte bool, err error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" || strings.EqualFold(trimmed, "generate") || strings.EqualFold(trimmed, "random") || strings.EqualFold(trimmed, "auto") {
		// Auto-generate 16 secure random bytes
		raw, unenc, err := GenerateSecureRandom16()
		if err != nil {
			return nil, 0, "", false, err
		}
		return raw[:], 0, unenc, true, nil
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

	// Case 4: Arbitrary semantic text (e.g. "ROOM-101", "pagar depan", etc.) -> Deterministic 16-byte SHA-256 hash
	h := sha256.Sum256([]byte(trimmed))
	raw16 = h[:16]
	unenc := "0" + base64.RawURLEncoding.EncodeToString(raw16)
	return raw16, 0, unenc, true, nil
}
