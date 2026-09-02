package crypto

import (
	"errors"
	"fmt"
	"strings"
)

// Base45Charset is the 45-character alphabet defined in RFC 9285.
const Base45Charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

var base45DecodeMap [256]int

func init() {
	for i := range base45DecodeMap {
		base45DecodeMap[i] = -1
	}
	for i, c := range Base45Charset {
		base45DecodeMap[c] = i
	}
}

// EncodeBase45 encodes binary data into an RFC 9285 Base45 string.
// Every 2 bytes (16 bits) are encoded into 3 characters in little-endian order.
// A single remaining byte is encoded into 2 characters.
func EncodeBase45(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var sb strings.Builder
	// 2 bytes -> 3 chars, 1 byte -> 2 chars
	sb.Grow((len(data)/2)*3 + (len(data)%2)*2)

	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			// 2-byte chunk
			val := (int(data[i]) << 8) | int(data[i+1])
			c := val / (45 * 45)
			rem := val % (45 * 45)
			d := rem / 45
			e := rem % 45
			// Little-endian order: e, d, c
			sb.WriteByte(Base45Charset[e])
			sb.WriteByte(Base45Charset[d])
			sb.WriteByte(Base45Charset[c])
		} else {
			// 1 remaining byte
			val := int(data[i])
			c := val / 45
			d := val % 45
			// Little-endian order: d, c
			sb.WriteByte(Base45Charset[d])
			sb.WriteByte(Base45Charset[c])
		}
	}

	return sb.String()
}

// DecodeBase45 decodes an RFC 9285 Base45 string back into raw bytes.
func DecodeBase45(str string) ([]byte, error) {
	if len(str) == 0 {
		return []byte{}, nil
	}

	// Length must not leave 1 character remaining (valid chunks are 3 or 2)
	if len(str)%3 == 1 {
		return nil, errors.New("invalid base45 string length: remainder of 1 character is not valid")
	}

	out := make([]byte, 0, (len(str)/3)*2+1)

	for i := 0; i < len(str); i += 3 {
		if i+2 < len(str) {
			// 3 characters -> 2 bytes
			c0 := base45DecodeMap[str[i]]
			c1 := base45DecodeMap[str[i+1]]
			c2 := base45DecodeMap[str[i+2]]

			if c0 == -1 || c1 == -1 || c2 == -1 {
				return nil, fmt.Errorf("invalid base45 character at position %d", i)
			}

			val := c0 + (c1 * 45) + (c2 * 45 * 45)
			if val > 65535 {
				return nil, fmt.Errorf("base45 integer overflow at position %d (val: %d > 65535)", i, val)
			}

			out = append(out, byte(val>>8), byte(val&0xFF))
		} else if i+1 < len(str) {
			// 2 characters -> 1 byte
			c0 := base45DecodeMap[str[i]]
			c1 := base45DecodeMap[str[i+1]]

			if c0 == -1 || c1 == -1 {
				return nil, fmt.Errorf("invalid base45 character at position %d", i)
			}

			val := c0 + (c1 * 45)
			if val > 255 {
				return nil, fmt.Errorf("base45 byte overflow at position %d (val: %d > 255)", i, val)
			}

			out = append(out, byte(val))
		}
	}

	return out, nil
}
