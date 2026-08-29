package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"consteon.com/vid-generator/internal/config"
	"consteon.com/vid-generator/internal/db"
	"consteon.com/vid-generator/internal/mcp"
	"consteon.com/vid-generator/internal/middleware"
	"consteon.com/vid-generator/internal/vid"
)

func main() {
	cfg := config.LoadFromEnv()
	log.Printf("Starting Consteon VID Generator MCP Service on port %s (env=%s, project=%s, db=%s)",
		cfg.Port, cfg.Environment, cfg.ProjectID, cfg.DatabaseID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Initialize Firestore client
	dbClient, err := db.NewClient(ctx, cfg.ProjectID, cfg.DatabaseID)
	if err != nil {
		log.Fatalf("Fatal: Failed to connect to Firestore: %v", err)
	}
	defer dbClient.Close()
	repo := db.NewRepository(dbClient)

	// 2. Build Seed Table & Generator Engine
	log.Println("Building empirical seed prefix table for cluster targeting...")
	seedTable := vid.NewSeedTable()
	generator := vid.NewGenerator(seedTable)
	validator := vid.NewValidator()
	log.Println("VID Generator Engine initialized successfully.")

	// 3. Initialize Compliance & Middleware components
	auditLogger := middleware.NewAuditLogger()
	authorizer := middleware.NewAuthorizer()

	// 4. Initialize MCP Server
	mcpServer := mcp.NewServer(generator, validator, repo, auditLogger, authorizer)
	httpHandler := mcp.NewHTTPHandler(mcpServer)

	// 5. Register HTTP Routes
	mux := http.NewServeMux()
	httpHandler.RegisterRoutes(mux)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 6. Graceful Shutdown listener
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("Server listening on http://0.0.0.0:%s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stopChan
	log.Println("Shutdown signal received, shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced shutdown error: %v", err)
	}
	log.Println("Consteon VID Generator stopped cleanly.")
}
