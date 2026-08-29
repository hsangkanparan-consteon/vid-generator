package vid

import (
	"errors"
	"fmt"
	"consteon.com/vid-generator/pkg/vidmath"
)

type ValidationResult struct {
	Valid         bool                      `json:"valid"`
	VID           vidmath.VID               `json:"vid"`
	Address       *vidmath.ExtractedAddress `json:"address,omitempty"`
	CountryCode   string                    `json:"country_code,omitempty"`
	CountryName   string                    `json:"country_name,omitempty"`
	ChecksumValid bool                      `json:"checksum_valid"`
	ClusterValid  bool                      `json:"cluster_valid"`
	Error         string                    `json:"error,omitempty"`
}

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(rawVID string) *ValidationResult {
	res := &ValidationResult{
		Valid: false,
		VID:   vidmath.VID(rawVID),
	}

	if len(rawVID) != 14 {
		res.Error = fmt.Sprintf("invalid length: expected 14 digits, got %d", len(rawVID))
		return res
	}

	chkOk, err := vidmath.ValidateChecksum(rawVID)
	if err != nil || !chkOk {
		res.ChecksumValid = false
		res.Error = "invalid checksum (last 2 digits do not match MOD-100 sum)"
		return res
	}
	res.ChecksumValid = true

	addr, err := vidmath.ExtractAddress(rawVID)
	if err != nil {
		res.Error = fmt.Sprintf("address extraction failed: %v", err)
		return res
	}
	res.Address = addr

	countryCode := DetermineCountryFromCluster(addr.Cluster)
	res.CountryCode = countryCode

	if r, err := GetCountryRange(countryCode); err == nil {
		res.CountryName = r.Name
		res.ClusterValid = true
	} else {
		res.CountryName = "Unknown"
		res.ClusterValid = false
	}

	res.Valid = true
	return res
}

func (v *Validator) AssertValid(rawVID string) error {
	res := v.Validate(rawVID)
	if !res.Valid {
		return errors.New(res.Error)
	}
	return nil
}
