package vid

import (
	"fmt"
	"strings"
	"consteon.com/vid-generator/pkg/vidmath"
)

// CountryRange defines the valid cluster range for a given country or system code.
type CountryRange struct {
	Code         string
	Name         string
	ClusterMin   vidmath.Cluster
	ClusterMax   vidmath.Cluster
	Description  string
}

// Supported country / system codes and their full 7-digit cluster ranges.
var SupportedCountries = map[string]CountryRange{
	"0": {
		Code:        "0",
		Name:        "System",
		ClusterMin:  0,
		ClusterMax:  999999,
		Description: "Internal Authenium system processes and automated tasks",
	},
	"1": {
		Code:        "1",
		Name:        "USA",
		ClusterMin:  1000000,
		ClusterMax:  1999999,
		Description: "United States users and organizations",
	},
	"424": {
		Code:        "424",
		Name:        "System 424",
		ClusterMin:  4240000,
		ClusterMax:  4249999,
		Description: "Proprietary Authenium core system VIDs",
	},
	"62": {
		Code:        "62",
		Name:        "Indonesia",
		ClusterMin:  6200000,
		ClusterMax:  6299999,
		Description: "Indonesia users, vehicles, and organizations",
	},
	"91": {
		Code:        "91",
		Name:        "India",
		ClusterMin:  9100000,
		ClusterMax:  9199999,
		Description: "India users and organizations",
	},
	"61": {
		Code:        "61",
		Name:        "Australia",
		ClusterMin:  6100000,
		ClusterMax:  6199999,
		Description: "Australia users and organizations",
	},
}

// GetCountryRange returns the CountryRange for a code, or error if unsupported.
func GetCountryRange(code string) (*CountryRange, error) {
	c := strings.TrimSpace(code)
	if r, ok := SupportedCountries[c]; ok {
		return &r, nil
	}
	return nil, fmt.Errorf("unsupported country code: '%s'", code)
}

// IsClusterInCountry checks if a cluster belongs to a country's allocated range.
func IsClusterInCountry(cluster vidmath.Cluster, code string) bool {
	r, err := GetCountryRange(code)
	if err != nil {
		return false
	}
	return cluster >= r.ClusterMin && cluster <= r.ClusterMax
}

// DetermineCountryFromCluster extracts the country code from a cluster ID.
func DetermineCountryFromCluster(cluster vidmath.Cluster) string {
	for code, r := range SupportedCountries {
		if cluster >= r.ClusterMin && cluster <= r.ClusterMax {
			return code
		}
	}
	return "unknown"
}
