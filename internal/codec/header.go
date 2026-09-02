package codec

import (
	"errors"
	"fmt"
)

// QRType represents the category of the QR code.
type QRType uint8

const (
	TypeLocation QRType = 1
	TypeAsset    QRType = 2
	TypeUser     QRType = 3
	TypeOther    QRType = 4

	FormatVersion1 uint8 = 1
	HeaderLength          = 2
	SignatureLength       = 64
)

var (
	ErrInvalidHeaderLength = errors.New("token header must be exactly 2 bytes")
	ErrUnsupportedType     = errors.New("unsupported QR code type")
	ErrUnsupportedVersion  = errors.New("unsupported format version")
)

// Header represents the 2-byte token header.
type Header struct {
	Type          QRType
	FormatVersion uint8
	KeyVersion    uint8
}

// EncodeHeader packs the Header into a 2-byte array.
func EncodeHeader(h Header) [HeaderLength]byte {
	typeNibble := (byte(h.Type) & 0x0F) << 4
	verNibble := (h.FormatVersion & 0x0F)
	return [HeaderLength]byte{
		typeNibble | verNibble,
		h.KeyVersion,
	}
}

// DecodeHeader parses the 2-byte header.
func DecodeHeader(b []byte) (Header, error) {
	if len(b) < HeaderLength {
		return Header{}, ErrInvalidHeaderLength
	}

	t := QRType((b[0] >> 4) & 0x0F)
	v := b[0] & 0x0F
	kv := b[1]

	if t < TypeLocation || t > TypeOther {
		return Header{}, fmt.Errorf("%w: %d", ErrUnsupportedType, t)
	}

	if v != FormatVersion1 {
		return Header{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, v)
	}

	return Header{
		Type:          t,
		FormatVersion: v,
		KeyVersion:    kv,
	}, nil
}

func (t QRType) String() string {
	switch t {
	case TypeLocation:
		return "location"
	case TypeAsset:
		return "asset"
	case TypeUser:
		return "user"
	case TypeOther:
		return "other"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
