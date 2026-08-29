package vid

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"consteon.com/vid-generator/pkg/vidmath"
)

// SeedPrefix represents a 2-digit high-order prefix (d1, d2).
type SeedPrefix struct {
	D1 int
	D2 int
}

// SeedTable stores candidate prefixes for each supported country code to accelerate cluster targeting.
type SeedTable struct {
	mu       sync.RWMutex
	prefixes map[string][]SeedPrefix
}

// NewSeedTable initializes and builds the seed prefix lookup table for all supported countries.
func NewSeedTable() *SeedTable {
	st := &SeedTable{
		prefixes: make(map[string][]SeedPrefix),
	}
	st.Build()
	return st
}

// Build pre-computes valid (d1, d2) prefixes for each supported country.
func (st *SeedTable) Build() {
	st.mu.Lock()
	defer st.mu.Unlock()

	countryHits := make(map[string]map[SeedPrefix]int)
	for code := range SupportedCountries {
		countryHits[code] = make(map[SeedPrefix]int)
	}

	samplesPerPrefix := 400
	for d1 := 0; d1 <= 9; d1++ {
		for d2 := 0; d2 <= 9; d2++ {
			prefix := SeedPrefix{D1: d1, D2: d2}

			for s := 0; s < samplesPerPrefix; s++ {
				randBuf := make([]byte, 10)
				for i := range randBuf {
					n, _ := rand.Int(rand.Reader, big.NewInt(10))
					randBuf[i] = byte('0' + n.Int64())
				}

				payload := fmt.Sprintf("%d%d%s", d1, d2, string(randBuf))
				addr, err := vidmath.ExtractAddress(payload)
				if err != nil {
					continue
				}

				country := DetermineCountryFromCluster(addr.Cluster)
				if country != "unknown" {
					countryHits[country][prefix]++
				}
			}
		}
	}

	for code, hitMap := range countryHits {
		var list []SeedPrefix
		for prefix, hits := range hitMap {
			if hits > 0 {
				list = append(list, prefix)
			}
		}

		if len(list) == 0 {
			// For narrow ranges, fallback to all (d1, d2) combinations
			for d1 := 0; d1 <= 9; d1++ {
				for d2 := 0; d2 <= 9; d2++ {
					list = append(list, SeedPrefix{D1: d1, D2: d2})
				}
			}
		}

		st.prefixes[code] = list
	}
}

// GetRandomPrefix picks a random seed prefix for the given country.
func (st *SeedTable) GetRandomPrefix(countryCode string) (SeedPrefix, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	list, ok := st.prefixes[countryCode]
	if !ok || len(list) == 0 {
		return SeedPrefix{0, 0}, fmt.Errorf("no seed prefixes for country: %s", countryCode)
	}

	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	if err != nil {
		return list[0], nil
	}

	return list[idx.Int64()], nil
}
