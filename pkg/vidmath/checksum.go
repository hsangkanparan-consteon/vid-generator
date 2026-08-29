package vidmath

import (
	"errors"
	"fmt"
	"strconv"
)

var (
	ErrInvalidVIDLength = errors.New("vid must be exactly 14 digits")
	ErrNonNumericVID    = errors.New("vid must contain only numeric digits")
	ErrInvalidChecksum  = errors.New("vid checksum verification failed")
)

// CalculateChecksum computes the 2-digit checksum for a 12-digit payload.
// Formula: MOD(pair1 + pair2 + pair3 + pair4 + pair5 + pair6, 100)
// where pair1=VID[0:2], pair2=VID[2:4], pair3=VID[4:6], pair4=VID[6:8], pair5=VID[8:10], pair6=VID[10:12].
func CalculateChecksum(payload12 string) (int, error) {
	if len(payload12) < 12 {
		return 0, fmt.Errorf("payload must be at least 12 digits, got %d", len(payload12))
	}

	sum := 0
	for i := 0; i < 12; i += 2 {
		pairVal, err := strconv.Atoi(payload12[i : i+2])
		if err != nil {
			return 0, fmt.Errorf("non-numeric pair at index %d: %w", i, err)
		}
		sum += pairVal
	}

	return sum % 100, nil
}

// FormatVID constructs a complete 14-digit VID from a 12-digit payload and its checksum.
func FormatVID(payload12 string) (VID, error) {
	if len(payload12) != 12 {
		return "", fmt.Errorf("payload must be exactly 12 digits, got %d", len(payload12))
	}
	chk, err := CalculateChecksum(payload12)
	if err != nil {
		return "", err
	}
	return VID(fmt.Sprintf("%s%02d", payload12, chk)), nil
}

// ValidateChecksum verifies if the 14-digit VID's last 2 digits match the computed checksum.
func ValidateChecksum(vidStr string) (bool, error) {
	if len(vidStr) != 14 {
		return false, ErrInvalidVIDLength
	}

	for _, r := range vidStr {
		if r < '0' || r > '9' {
			return false, ErrNonNumericVID
		}
	}

	expectedChk, err := CalculateChecksum(vidStr[0:12])
	if err != nil {
		return false, err
	}

	actualChk, err := strconv.Atoi(vidStr[12:14])
	if err != nil {
		return false, err
	}

	return expectedChk == actualChk, nil
}
