package tests

import (
	"testing"
	"consteon.com/vid-generator/internal/vid"
	"consteon.com/vid-generator/pkg/vidmath"
)

func TestSampleVIDVerification(t *testing.T) {
	// All 5 samples provided by the user belong to cluster 6200000 (Indonesia)
	samples := []struct {
		vid             string
		expectedAddress vidmath.Address
		expectedCluster vidmath.Cluster
		expectedPos     vidmath.Position
		expectedCountry string
	}{
		{
			vid:             "11306930191372",
			expectedAddress: 620000082277,
			expectedCluster: 6200000,
			expectedPos:     82277,
			expectedCountry: "62",
		},
		{
			vid:             "28048604621802",
			expectedAddress: 620000081320,
			expectedCluster: 6200000,
			expectedPos:     81320,
			expectedCountry: "62",
		},
		{
			vid:             "41009900933063",
			expectedAddress: 620000077590,
			expectedCluster: 6200000,
			expectedPos:     77590,
			expectedCountry: "62",
		},
		{
			vid:             "54601259181114",
			expectedAddress: 620000018757,
			expectedCluster: 6200000,
			expectedPos:     18757,
			expectedCountry: "62",
		},
		{
			vid:             "63872187026727",
			expectedAddress: 620000025621,
			expectedCluster: 6200000,
			expectedPos:     25621,
			expectedCountry: "62",
		},
	}

	validator := vid.NewValidator()

	for _, s := range samples {
		t.Run("VID_"+s.vid, func(t *testing.T) {
			res := validator.Validate(s.vid)
			if !res.Valid {
				t.Fatalf("Expected VID %s to be valid, got error: %s", s.vid, res.Error)
			}
			if !res.ChecksumValid {
				t.Fatalf("Expected checksum to be valid for %s", s.vid)
			}
			if res.Address.Address != s.expectedAddress {
				t.Errorf("Address mismatch for %s: got %d, want %d", s.vid, res.Address.Address, s.expectedAddress)
			}
			if res.Address.Cluster != s.expectedCluster {
				t.Errorf("Cluster mismatch for %s: got %d, want %d", s.vid, res.Address.Cluster, s.expectedCluster)
			}
			if res.Address.Position != s.expectedPos {
				t.Errorf("Position mismatch for %s: got %d, want %d", s.vid, res.Address.Position, s.expectedPos)
			}
			if res.CountryCode != s.expectedCountry {
				t.Errorf("Country code mismatch for %s: got %s, want %s", s.vid, res.CountryCode, s.expectedCountry)
			}
		})
	}
}

func TestBatchGenerator(t *testing.T) {
	st := vid.NewSeedTable()
	gen := vid.NewGenerator(st)

	countries := []string{"62", "1", "91", "0", "424"}

	for _, c := range countries {
		t.Run("Generate_Country_"+c, func(t *testing.T) {
			res, err := gen.GenerateBatch(c, 25)
			if err != nil {
				t.Fatalf("Failed to generate batch for country %s: %v", c, err)
			}
			if len(res.VIDs) != 25 {
				t.Errorf("Expected 25 VIDs, got %d", len(res.VIDs))
			}

			seen := make(map[vidmath.Address]bool)
			for _, item := range res.VIDs {
				if seen[item.Address.Address] {
					t.Errorf("Duplicate address generated within batch: %d", item.Address.Address)
				}
				seen[item.Address.Address] = true

				if !vid.IsClusterInCountry(item.Address.Cluster, c) {
					t.Errorf("VID %s cluster %d not in country %s range", item.VID, item.Address.Cluster, c)
				}
			}
		})
	}
}
