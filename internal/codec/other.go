package codec

import (
	"errors"
	"fmt"
)

// OtherPayload represents the unpacked Other/IoT/Process QR code fields.
type OtherPayload struct {
	Subtype  uint8  // 1 byte (e.g. 1=IoT, 2=Process, 3=Project)
	EntityID string // 14-digit numeric string or 6-byte packed ID
	Metadata []byte // Subtype-specific metadata
}

// EncodeOtherPayload packs OtherPayload into binary slice.
func EncodeOtherPayload(p OtherPayload) ([]byte, error) {
	idBytes, err := EncodeVID14ToBytes(p.EntityID)
	if err != nil {
		return nil, fmt.Errorf("invalid entity ID: %w", err)
	}

	if len(p.Metadata) > 255 {
		return nil, errors.New("metadata exceeds maximum length of 255 bytes")
	}

	totalLen := 1 + 6 + 1 + len(p.Metadata) // 8 + metadata
	buf := make([]byte, totalLen)

	// 1. Subtype (1 byte)
	buf[0] = p.Subtype

	// 2. Entity ID (6 bytes)
	copy(buf[1:7], idBytes[:])

	// 3. Metadata Length (1 byte)
	buf[7] = byte(len(p.Metadata))

	// 4. Metadata (N bytes)
	copy(buf[8:], p.Metadata)

	return buf, nil
}

// DecodeOtherPayload parses binary slice into OtherPayload.
func DecodeOtherPayload(b []byte) (OtherPayload, error) {
	if len(b) < 8 {
		return OtherPayload{}, errors.New("insufficient bytes for Other payload (minimum 8 bytes)")
	}

	subtype := b[0]
	entityID, err := DecodeBytesToVID14(b[1:7])
	if err != nil {
		return OtherPayload{}, err
	}
	metaLen := int(b[7])

	if len(b) < 8+metaLen {
		return OtherPayload{}, fmt.Errorf("buffer truncated: expected %d bytes metadata, got %d", metaLen, len(b)-8)
	}

	metadata := make([]byte, metaLen)
	copy(metadata, b[8:8+metaLen])

	return OtherPayload{
		Subtype:  subtype,
		EntityID: entityID,
		Metadata: metadata,
	}, nil
}
