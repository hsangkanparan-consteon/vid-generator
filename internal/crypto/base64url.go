package crypto

import (
	"encoding/base64"
	"strings"
)

// EncodeBase64URL encodes byte slices into URL-safe unpadded Base64 strings.
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL decodes URL-safe Base64 strings (handles padded or unpadded).
func DecodeBase64URL(s string) ([]byte, error) {
	clean := strings.TrimSpace(s)
	// Try RawURLEncoding first (no padding)
	decoded, err := base64.RawURLEncoding.DecodeString(clean)
	if err == nil {
		return decoded, nil
	}
	// Fall back to standard URLEncoding (with padding)
	return base64.URLEncoding.DecodeString(clean)
}
