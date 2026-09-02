package codec

import (
	"errors"
)

const (
	UserPayloadLength = 6                                                       // 14-digit VID packed in 6 bytes (uint48)
	UserTokenLength   = HeaderLength + UserPayloadLength + SignatureLength     // 2 + 6 + 64 = 72 bytes
)

// UserPayload represents the unpacked User QR code fields.
type UserPayload struct {
	VID string // 14-digit numeric VID string (e.g. "12345678901234")
}

// EncodeUserPayload packs UserPayload into 6 bytes.
func EncodeUserPayload(p UserPayload) ([UserPayloadLength]byte, error) {
	return EncodeVID14ToBytes(p.VID)
}

// DecodeUserPayload parses 6 bytes into UserPayload.
func DecodeUserPayload(b []byte) (UserPayload, error) {
	if len(b) < UserPayloadLength {
		return UserPayload{}, errors.New("insufficient bytes for User payload (need 6 bytes)")
	}

	vid, err := DecodeBytesToVID14(b[:UserPayloadLength])
	if err != nil {
		return UserPayload{}, err
	}

	return UserPayload{
		VID: vid,
	}, nil
}
