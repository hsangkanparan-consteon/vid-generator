package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port                string
	ProjectID           string
	DatabaseID          string
	Environment         string
	LogLevel            string
	Region              string
	StockAlertThreshold int
}

func LoadFromEnv() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	projectID := os.Getenv("PROJECT_ID")
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if projectID == "" {
		projectID = "authenium-prod1"
	}

	databaseID := os.Getenv("DATABASE_ID")
	if databaseID == "" {
		databaseID = "vid-registry"
	}

	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "production"
	}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}

	region := os.Getenv("REGION")
	if region == "" {
		region = "asia-southeast1"
	}

	thresholdStr := os.Getenv("STOCK_ALERT_THRESHOLD")
	threshold := 5000
	if val, err := strconv.Atoi(thresholdStr); err == nil && val > 0 {
		threshold = val
	}

	return &Config{
		Port:                port,
		ProjectID:           projectID,
		DatabaseID:          databaseID,
		Environment:         env,
		LogLevel:            logLevel,
		Region:              region,
		StockAlertThreshold: threshold,
	}
}
