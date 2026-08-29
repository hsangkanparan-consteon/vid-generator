package migration

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"consteon.com/vid-generator/internal/db"
	"consteon.com/vid-generator/internal/vid"
)

type ImportSummary struct {
	TotalRows     int           `json:"total_rows"`
	Imported      int           `json:"imported"`
	Duplicates    int           `json:"duplicates"`
	InvalidVIDs   int           `json:"invalid_vids"`
	ExecutionTime time.Duration `json:"execution_time"`
}

type Importer struct {
	validator *vid.Validator
	repo      *db.Repository
}

func NewImporter(v *vid.Validator, repo *db.Repository) *Importer {
	return &Importer{
		validator: v,
		repo:      repo,
	}
}

func (imp *Importer) ImportCSV(ctx context.Context, filePath string) (*ImportSummary, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	startTime := time.Now()

	summary := &ImportSummary{}
	var candidates []*vid.GeneratedVID

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading CSV: %w", err)
		}

		if len(record) == 0 {
			continue
		}

		rawVID := strings.TrimSpace(record[0])
		summary.TotalRows++

		if strings.EqualFold(rawVID, "vid") || strings.EqualFold(rawVID, "id") {
			continue
		}

		res := imp.validator.Validate(rawVID)
		if !res.Valid {
			summary.InvalidVIDs++
			continue
		}

		candidates = append(candidates, &vid.GeneratedVID{
			VID:      res.VID,
			Address:  *res.Address,
			Country:  res.CountryCode,
			Attempts: 1,
		})

		if len(candidates) >= 500 {
			ins, dup, err := imp.repo.CreateStockBatch(ctx, candidates, db.StatusInUse)
			if err != nil {
				return nil, fmt.Errorf("batch insert failed: %w", err)
			}
			summary.Imported += ins
			summary.Duplicates += dup
			candidates = candidates[:0]
		}
	}

	if len(candidates) > 0 {
		ins, dup, err := imp.repo.CreateStockBatch(ctx, candidates, db.StatusInUse)
		if err != nil {
			return nil, fmt.Errorf("final batch insert failed: %w", err)
		}
		summary.Imported += ins
		summary.Duplicates += dup
	}

	summary.ExecutionTime = time.Since(startTime)
	return summary, nil
}
