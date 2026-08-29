package vid

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"consteon.com/vid-generator/pkg/vidmath"
)

type GeneratedVID struct {
	VID      vidmath.VID              `json:"vid"`
	Address  vidmath.ExtractedAddress `json:"address"`
	Country  string                   `json:"country"`
	Attempts int                      `json:"attempts"`
}

type BatchGenerationResult struct {
	VIDs          []*GeneratedVID `json:"vids"`
	Country       string          `json:"country"`
	Requested     int             `json:"requested"`
	Generated     int             `json:"generated"`
	TotalAttempts int             `json:"total_attempts"`
	Collisions    int             `json:"collisions"`
	DurationMs    int64           `json:"duration_ms"`
	HitRate       float64         `json:"hit_rate_pct"`
}

type Generator struct {
	seedTable *SeedTable
}

func NewGenerator(st *SeedTable) *Generator {
	if st == nil {
		st = NewSeedTable()
	}
	return &Generator{
		seedTable: st,
	}
}

func (g *Generator) GenerateOne(countryCode string) (*GeneratedVID, error) {
	_, err := GetCountryRange(countryCode)
	if err != nil {
		return nil, err
	}

	maxAttempts := 5000
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		prefix, err := g.seedTable.GetRandomPrefix(countryCode)
		if err != nil {
			return nil, err
		}

		randDigits := make([]byte, 10)
		for i := 0; i < 10; i++ {
			n, err := rand.Int(rand.Reader, big.NewInt(10))
			if err != nil {
				return nil, fmt.Errorf("csprng error: %w", err)
			}
			randDigits[i] = byte('0' + n.Int64())
		}

		payload := fmt.Sprintf("%d%d%s", prefix.D1, prefix.D2, string(randDigits))
		addr, err := vidmath.ExtractAddress(payload)
		if err != nil {
			continue
		}

		if !IsClusterInCountry(addr.Cluster, countryCode) {
			continue
		}

		fullVID, err := vidmath.FormatVID(payload)
		if err != nil {
			continue
		}

		return &GeneratedVID{
			VID:      fullVID,
			Address:  *addr,
			Country:  countryCode,
			Attempts: attempt,
		}, nil
	}

	return nil, errors.New("exceeded maximum attempts to generate VID in target cluster range")
}

func (g *Generator) GenerateBatch(countryCode string, count int) (*BatchGenerationResult, error) {
	if count <= 0 {
		return nil, errors.New("count must be greater than 0")
	}
	if count > 10000 {
		return nil, errors.New("count cannot exceed 10,000 per batch")
	}

	startTime := time.Now()

	numWorkers := 4
	if count >= 1000 {
		numWorkers = 8
	}

	var mu sync.Mutex
	uniqueMap := make(map[vidmath.Address]*GeneratedVID)
	totalAttempts := 0
	collisions := 0

	var wg sync.WaitGroup
	errChan := make(chan error, numWorkers)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				if len(uniqueMap) >= count {
					mu.Unlock()
					return
				}
				mu.Unlock()

				item, err := g.GenerateOne(countryCode)
				if err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}

				mu.Lock()
				totalAttempts += item.Attempts
				if len(uniqueMap) < count {
					if _, exists := uniqueMap[item.Address.Address]; exists {
						collisions++
					} else {
						uniqueMap[item.Address.Address] = item
					}
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 && len(uniqueMap) < count {
		return nil, <-errChan
	}

	resultList := make([]*GeneratedVID, 0, len(uniqueMap))
	for _, v := range uniqueMap {
		resultList = append(resultList, v)
	}

	duration := time.Since(startTime).Milliseconds()
	hitRate := 0.0
	if totalAttempts > 0 {
		hitRate = (float64(len(resultList)) / float64(totalAttempts)) * 100.0
	}

	return &BatchGenerationResult{
		VIDs:          resultList,
		Country:       countryCode,
		Requested:     count,
		Generated:     len(resultList),
		TotalAttempts: totalAttempts,
		Collisions:    collisions,
		DurationMs:    duration,
		HitRate:       hitRate,
	}, nil
}
