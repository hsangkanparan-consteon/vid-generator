package codec

import (
	"bytes"
	"testing"
)

func TestLocationCodecRoundTrip(t *testing.T) {
	// Case 1: With UID (8 bytes payload)
	origWithUID := LocationPayload{
		CountryCode: 360, // Indonesia
		Subtype:     LocSubtypeGate,
		HasUID:      true,
		LocationUID: 987654321,
	}

	packed := EncodeLocationPayload(origWithUID)
	if len(packed) != LocationPayloadWithUIDLength {
		t.Fatalf("expected length %d, got %d", LocationPayloadWithUIDLength, len(packed))
	}

	decoded, err := DecodeLocationPayload(packed)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	if decoded.CountryCode != origWithUID.CountryCode || decoded.Subtype != origWithUID.Subtype || decoded.LocationUID != origWithUID.LocationUID || !decoded.HasUID {
		t.Errorf("location with UID mismatch: got %+v, expected %+v", decoded, origWithUID)
	}

	// Case 2: Without UID (3 bytes payload)
	origNoUID := LocationPayload{
		CountryCode: 360,
		Subtype:     LocSubtypeRoom,
		HasUID:      false,
	}

	packedNoUID := EncodeLocationPayload(origNoUID)
	if len(packedNoUID) != LocationPayloadWithoutUIDLength {
		t.Fatalf("expected length %d, got %d", LocationPayloadWithoutUIDLength, len(packedNoUID))
	}

	decodedNoUID, err := DecodeLocationPayload(packedNoUID)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	if decodedNoUID.CountryCode != origNoUID.CountryCode || decodedNoUID.Subtype != origNoUID.Subtype || decodedNoUID.HasUID {
		t.Errorf("location without UID mismatch: got %+v, expected %+v", decodedNoUID, origNoUID)
	}
}

func TestAssetCodecRoundTrip(t *testing.T) {
	// Case 1: With UID (8 bytes payload)
	testCases := []struct {
		unspsc   string
		assetUID uint64
	}{
		{"251015", 123456},
		{"432115", 999999999},
		{"2510", 88888},
		{"401017", 1},
	}

	for _, tc := range testCases {
		t.Run("WithUID_"+tc.unspsc, func(t *testing.T) {
			orig := AssetPayload{
				UNSPSC:   tc.unspsc,
				HasUID:   true,
				AssetUID: tc.assetUID,
			}

			packed, err := EncodeAssetPayload(orig)
			if err != nil {
				t.Fatalf("unexpected error encoding asset: %v", err)
			}

			if len(packed) != AssetPayloadWithUIDLength {
				t.Fatalf("expected length %d, got %d", AssetPayloadWithUIDLength, len(packed))
			}

			decoded, err := DecodeAssetPayload(packed)
			if err != nil {
				t.Fatalf("unexpected error decoding asset: %v", err)
			}

			if decoded.UNSPSC != orig.UNSPSC {
				t.Errorf("UNSPSC mismatch: got %s, expected %s", decoded.UNSPSC, orig.UNSPSC)
			}
			if decoded.AssetUID != orig.AssetUID || !decoded.HasUID {
				t.Errorf("Asset UID mismatch: got %d (has_uid=%v), expected %d", decoded.AssetUID, decoded.HasUID, orig.AssetUID)
			}
		})
	}

	// Case 2: Without UID (3 bytes payload)
	t.Run("WithoutUID_251015", func(t *testing.T) {
		orig := AssetPayload{
			UNSPSC: "251015",
			HasUID: false,
		}

		packed, err := EncodeAssetPayload(orig)
		if err != nil {
			t.Fatalf("unexpected error encoding asset without UID: %v", err)
		}

		if len(packed) != AssetPayloadWithoutUIDLength {
			t.Fatalf("expected length %d, got %d", AssetPayloadWithoutUIDLength, len(packed))
		}

		decoded, err := DecodeAssetPayload(packed)
		if err != nil {
			t.Fatalf("unexpected error decoding asset without UID: %v", err)
		}

		if decoded.UNSPSC != orig.UNSPSC || decoded.HasUID {
			t.Errorf("mismatch: got %+v, expected %+v", decoded, orig)
		}
	})
}

func TestUserCodecRoundTrip(t *testing.T) {
	orig := UserPayload{
		VID: "12345678901234",
	}

	packed, err := EncodeUserPayload(orig)
	if err != nil {
		t.Fatalf("unexpected error encoding user: %v", err)
	}

	if len(packed) != UserPayloadLength {
		t.Fatalf("expected length %d, got %d", UserPayloadLength, len(packed))
	}

	decoded, err := DecodeUserPayload(packed[:])
	if err != nil {
		t.Fatalf("unexpected error decoding user: %v", err)
	}

	if decoded.VID != orig.VID {
		t.Errorf("VID mismatch: got %s, expected %s", decoded.VID, orig.VID)
	}
}

func TestOtherCodecRoundTrip(t *testing.T) {
	meta := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	orig := OtherPayload{
		Subtype:  1, // IoT
		EntityID: "10002000300040",
		Metadata: meta,
	}

	packed, err := EncodeOtherPayload(orig)
	if err != nil {
		t.Fatalf("unexpected error encoding other: %v", err)
	}

	decoded, err := DecodeOtherPayload(packed)
	if err != nil {
		t.Fatalf("unexpected error decoding other: %v", err)
	}

	if decoded.EntityID != orig.EntityID {
		t.Errorf("entity ID mismatch: got %s, expected %s", decoded.EntityID, orig.EntityID)
	}
	if !bytes.Equal(decoded.Metadata, orig.Metadata) {
		t.Errorf("metadata mismatch: got %x, expected %x", decoded.Metadata, orig.Metadata)
	}
}

func TestHeaderCodecRoundTrip(t *testing.T) {
	orig := Header{
		Type:          TypeLocation,
		FormatVersion: FormatVersion1,
		KeyVersion:    1,
	}

	packed := EncodeHeader(orig)
	decoded, err := DecodeHeader(packed[:])
	if err != nil {
		t.Fatalf("unexpected error decoding header: %v", err)
	}

	if decoded != orig {
		t.Errorf("header mismatch: got %+v, expected %+v", decoded, orig)
	}
}
