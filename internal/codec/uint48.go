package codec

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrInvalidVIDLength = errors.New("VID must be a 14-digit numeric string")
	ErrInvalidVIDFormat = errors.New("VID contains non-numeric characters")
	ErrValueOverflow    = errors.New("value exceeds maximum 48-bit integer capacity")
)

// MaxUint48 is the maximum value that fits in 6 bytes (48 bits): 281,474,976,710,655.
const MaxUint48 = (uint64(1) << 48) - 1

// MaxUint40 is the maximum value that fits in 5 bytes (40 bits): 1,099,511,627,775.
const MaxUint40 = (uint64(1) << 40) - 1

// EncodeVID14ToBytes converts a 14-digit numeric string (e.g. "10002000300040" or "00000000000000")
// into a 6-byte big-endian byte array.
func EncodeVID14ToBytes(vid string) ([6]byte, error) {
	var result [6]byte
	if len(vid) != 14 {
		return result, ErrInvalidVIDLength
	}

	val, err := strconv.ParseUint(vid, 10, 64)
	if err != nil {
		return result, ErrInvalidVIDFormat
	}

	if val > MaxUint48 {
		return result, ErrValueOverflow
	}

	result[0] = byte(val >> 40)
	result[1] = byte(val >> 32)
	result[2] = byte(val >> 24)
	result[3] = byte(val >> 16)
	result[4] = byte(val >> 8)
	result[5] = byte(val)

	return result, nil
}

// DecodeBytesToVID14 converts a 6-byte big-endian byte array back into a 14-digit formatted numeric string.
func DecodeBytesToVID14(b []byte) (string, error) {
	if len(b) < 6 {
		return "", errors.New("byte slice must have at least 6 bytes for 14-digit VID")
	}

	val := (uint64(b[0]) << 40) |
		(uint64(b[1]) << 32) |
		(uint64(b[2]) << 24) |
		(uint64(b[3]) << 16) |
		(uint64(b[4]) << 8) |
		uint64(b[5])

	return fmt.Sprintf("%014d", val), nil
}

// EncodeUint24 packs a uint32 (up to 16,777,215) into 3 bytes big-endian.
func EncodeUint24(val uint32) [3]byte {
	return [3]byte{
		byte(val >> 16),
		byte(val >> 8),
		byte(val),
	}
}

// DecodeUint24 unpacks 3 bytes big-endian into a uint32.
func DecodeUint24(b []byte) uint32 {
	return (uint32(b[0]) << 16) | (uint32(b[1]) << 8) | uint32(b[2])
}

// EncodeUint40 packs a uint64 (up to 1,099,511,627,775) into 5 bytes big-endian.
func EncodeUint40(val uint64) [5]byte {
	return [5]byte{
		byte(val >> 32),
		byte(val >> 24),
		byte(val >> 16),
		byte(val >> 8),
		byte(val),
	}
}

// DecodeUint40 unpacks 5 bytes big-endian into a uint64.
func DecodeUint40(b []byte) uint64 {
	return (uint64(b[0]) << 32) |
		(uint64(b[1]) << 24) |
		(uint64(b[2]) << 16) |
		(uint64(b[3]) << 8) |
		uint64(b[4])
}

// GenerateRandomUID40 generates a cryptographically secure random 40-bit unique identifier (1 to 1,099,511,627,775).
func GenerateRandomUID40() (uint64, error) {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("failed to generate secure random UID: %w", err)
	}
	val := DecodeUint40(b[:])
	if val == 0 {
		val = 1
	}
	return val, nil
}

// ResolveUID40 resolves any user-supplied UID string (or empty) into a 40-bit integer:
// 1. If empty or "0": generates 5 cryptographically secure random bytes directly (CSPRNG).
// 2. If numeric string (<= 1,099,511,627,775): parses directly as a 40-bit integer.
// 3. If mixed text / lengthy string (e.g. "CAR-2026-XYZ-998812"): SHA-256 hashes to 5 bytes deterministically.
func ResolveUID40(input string) (uint64, error) {
	clean := strings.TrimSpace(input)
	if clean == "" || clean == "0" {
		return GenerateRandomUID40()
	}

	// 1. Try pure numeric parsing
	if val, err := strconv.ParseUint(clean, 10, 64); err == nil && val <= MaxUint40 {
		if val == 0 {
			return GenerateRandomUID40()
		}
		return val, nil
	}

	// 2. Mixed text: SHA-256 hash to 5 bytes
	hash := sha256.Sum256([]byte(clean))
	val := DecodeUint40(hash[:5])
	if val == 0 {
		val = 1
	}
	return val, nil
}
