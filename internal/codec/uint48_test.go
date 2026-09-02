package codec

import (
	"testing"
)

func TestVID14CodecRoundTrip(t *testing.T) {
	testCases := []string{
		"00000000000000",
		"00000000000001",
		"10002000300040",
		"99999999999999",
		"12345678901234",
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			packed, err := EncodeVID14ToBytes(tc)
			if err != nil {
				t.Fatalf("unexpected error encoding %s: %v", tc, err)
			}

			unpacked, err := DecodeBytesToVID14(packed[:])
			if err != nil {
				t.Fatalf("unexpected error decoding %x: %v", packed, err)
			}

			if unpacked != tc {
				t.Errorf("roundtrip mismatch: got %s, expected %s", unpacked, tc)
			}
		})
	}
}

func TestVID14InvalidInputs(t *testing.T) {
	invalidCases := []string{
		"12345",              // Too short
		"123456789012345",    // Too long
		"1234567890123a",    // Non-numeric
		"abcdefghijklmn",    // Letters
	}

	for _, tc := range invalidCases {
		_, err := EncodeVID14ToBytes(tc)
		if err == nil {
			t.Errorf("expected error for invalid VID %s, got nil", tc)
		}
	}
}

func TestUint24Codec(t *testing.T) {
	testValues := []uint32{0, 1, 841510, 16777215}
	for _, val := range testValues {
		packed := EncodeUint24(val)
		unpacked := DecodeUint24(packed[:])
		if unpacked != val {
			t.Errorf("Uint24 mismatch: got %d, expected %d", unpacked, val)
		}
	}
}

func TestUint40Codec(t *testing.T) {
	testValues := []uint64{0, 1, 123456789, 1099511627775}
	for _, val := range testValues {
		packed := EncodeUint40(val)
		unpacked := DecodeUint40(packed[:])
		if unpacked != val {
			t.Errorf("Uint40 mismatch: got %d, expected %d", unpacked, val)
		}
	}
}

func TestResolveUID40(t *testing.T) {
	// Case 1: Empty / "0" -> Random CSPRNG UID (> 0)
	u1, err := ResolveUID40("")
	if err != nil || u1 == 0 {
		t.Errorf("expected non-zero random UID for empty string, got %d", u1)
	}

	u2, err := ResolveUID40("0")
	if err != nil || u2 == 0 {
		t.Errorf("expected non-zero random UID for '0', got %d", u2)
	}

	// Case 2: Pure numeric string
	u3, err := ResolveUID40("123456789")
	if err != nil || u3 != 123456789 {
		t.Errorf("expected 123456789, got %d", u3)
	}

	// Case 3: Mixed text string (Deterministic Hash)
	text := "CAR-2026-XYZ-998812"
	u4, err := ResolveUID40(text)
	if err != nil || u4 == 0 {
		t.Errorf("expected valid hash UID for '%s', got %d", text, u4)
	}

	// Verify determinism
	u5, _ := ResolveUID40(text)
	if u4 != u5 {
		t.Errorf("expected deterministic hash match: got %d and %d", u4, u5)
	}
}
