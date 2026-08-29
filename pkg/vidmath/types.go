package vidmath

import "fmt"

// VID represents a 14-digit Versatile ID.
type VID string

// Address represents a 12-digit numeric address extracted from a VID.
type Address int64

// Cluster represents a 7-digit cluster ID.
type Cluster int64

// Position represents a 5-digit position index (00000 - 99999).
type Position int32

// ExtractedAddress contains full decomposition of a VID's address.
type ExtractedAddress struct {
	Address  Address  `json:"address"`
	Cluster  Cluster  `json:"cluster"`
	Position Position `json:"position"`
}

// String returns formatted 12-digit zero-padded string of the Address.
func (a Address) String() string {
	return fmt.Sprintf("%012d", a)
}

// String returns formatted 7-digit zero-padded string of the Cluster.
func (c Cluster) String() string {
	return fmt.Sprintf("%07d", c)
}

// String returns formatted 5-digit zero-padded string of the Position.
func (p Position) String() string {
	return fmt.Sprintf("%05d", p)
}
