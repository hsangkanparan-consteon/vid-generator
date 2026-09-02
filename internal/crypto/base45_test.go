package crypto

import (
	"bytes"
	"testing"
)

func TestRFC9285TestVectors(t *testing.T) {
	tests := []struct {
		input  string
		base45 string
	}{
		{"AB", "BB8"},
		{"Hello!!", "%69 VD92EX0"},
		{"base-45", "UJCLQE7W581"},
		{"ietf!", "QED8WEX0"},
	}

	for _, tt := range tests {
		encoded := EncodeBase45([]byte(tt.input))
		if encoded != tt.base45 {
			t.Errorf("EncodeBase45(%q) = %q, expected %q", tt.input, encoded, tt.base45)
		}

		decoded, err := DecodeBase45(tt.base45)
		if err != nil {
			t.Errorf("DecodeBase45(%q) error: %v", tt.base45, err)
		}
		if string(decoded) != tt.input {
			t.Errorf("DecodeBase45(%q) = %q, expected %q", tt.base45, string(decoded), tt.input)
		}
	}
}

func TestBase45UserQRRoundtrip(t *testing.T) {
	// 72-byte payload (2B header + 6B payload + 64B sig)
	data := make([]byte, 72)
	for i := range data {
		data[i] = byte(i * 3)
	}

	encoded := EncodeBase45(data)
	if len(encoded) != 108 {
		t.Fatalf("Expected 108 Base45 chars for 72 raw bytes, got %d chars: %s", len(encoded), encoded)
	}

	decoded, err := DecodeBase45(encoded)
	if err != nil {
		t.Fatalf("DecodeBase45 failed: %v", err)
	}

	if !bytes.Equal(data, decoded) {
		t.Fatalf("Decoded data does not match original")
	}
}
