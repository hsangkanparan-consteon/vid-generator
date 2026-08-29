package vidmath

import (
	"errors"
	"fmt"
	"strconv"
)

var (
	ErrPayloadTooShort = errors.New("vid payload must be at least 12 digits")
)

// ExtractAddress extracts Address, Cluster, and Position from a 12-digit payload or 14-digit VID string.
func ExtractAddress(vidStr string) (*ExtractedAddress, error) {
	if len(vidStr) < 12 {
		return nil, ErrPayloadTooShort
	}

	// Validate numeric characters
	for i := 0; i < 12; i++ {
		if vidStr[i] < '0' || vidStr[i] > '9' {
			return nil, fmt.Errorf("non-numeric character '%c' at index %d", vidStr[i], i)
		}
	}

	seg1, _ := strconv.ParseInt(vidStr[0:7], 10, 64)
	seg2, _ := strconv.ParseInt(vidStr[1:8], 10, 64)
	seg3, _ := strconv.ParseInt(vidStr[2:9], 10, 64)
	seg4, _ := strconv.ParseInt(vidStr[3:10], 10, 64)

	seg5, _ := strconv.ParseInt(vidStr[4:8], 10, 64)
	seg6, _ := strconv.ParseInt(vidStr[6:10], 10, 64)
	seg7, _ := strconv.ParseInt(vidStr[8:12], 10, 64)

	sumSegs := seg1 + seg2 + seg3 + seg4
	product := seg6 * seg7

	rawAddress := (sumSegs * 100000) + seg5 + product
	addressVal := rawAddress % 1000000000000 // MOD 10^12

	clusterVal := addressVal / 100000
	positionVal := addressVal % 100000

	return &ExtractedAddress{
		Address:  Address(addressVal),
		Cluster:  Cluster(clusterVal),
		Position: Position(positionVal),
	}, nil
}
