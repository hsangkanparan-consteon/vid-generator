package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"consteon.com/qr-generator/internal/api"
	"consteon.com/qr-generator/internal/dedup"
	"consteon.com/qr-generator/internal/keystore"
	"consteon.com/qr-generator/internal/kms"
	"consteon.com/qr-generator/internal/mcp"
)

func main() {
	stdioFlag := flag.Bool("stdio", false, "Run as MCP Stdio Server (for local IDE/Claude/Cursor integration)")
	flag.Parse()

	kmsKeyName := os.Getenv("GCP_KMS_KEY_NAME")
	if kmsKeyName == "" {
		kmsKeyName = os.Getenv("KMS_KEY_NAME")
	}
	gcsBucket := os.Getenv("GCS_KEYSTORE_BUCKET")
	if gcsBucket == "" {
		gcsBucket = os.Getenv("STORAGE_BUCKET_NAME")
	}
	useMockKMS := os.Getenv("USE_MOCK_KMS") == "true" || kmsKeyName == ""
	oidcAudience := os.Getenv("OIDC_AUDIENCE")
	isStdio := *stdioFlag || os.Getenv("MCP_STDIO") == "true"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var kmsClient kms.KMSClient
	var err error

	if useMockKMS {
		if !isStdio {
			log.Println("[INFO] Initializing In-Memory Mock KMS (for local testing/dev)...")
		}
		kmsClient, err = kms.NewMockKMSClient()
		if err != nil {
			log.Fatalf("Failed to initialize mock KMS: %v", err)
		}
	} else {
		if !isStdio {
			log.Printf("[INFO] Connecting to Google Cloud KMS: %s", kmsKeyName)
		}
		kmsClient, err = kms.NewGCPKMSClient(ctx, kmsKeyName)
		if err != nil {
			log.Fatalf("Failed to initialize GCP KMS client: %v", err)
		}
	}

	// Initialize Keystore (Persistent GCS bucket in production, or In-Memory in dev)
	var store keystore.Keystore
	if gcsBucket != "" && !useMockKMS {
		log.Printf("[INFO] Initializing Persistent GCS Keystore: gs://%s", gcsBucket)
		gcsStore, err := keystore.NewGCSKeystore(ctx, gcsBucket, kmsClient)
		if err != nil {
			log.Fatalf("Failed to initialize GCS Keystore: %v", err)
		}
		store = gcsStore
	} else {
		store = keystore.NewEncryptedKeystore(kmsClient)
	}

	// Initialize Real-Time Firestore Public Key Syncer for Mobile Scanner Distribution
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		projectID = os.Getenv("PROJECT_ID")
	}
	if projectID == "" && !useMockKMS {
		projectID = "authenium-prod1"
	}
	if projectID != "" && !useMockKMS {
		fsSyncer, err := keystore.NewFirestoreSyncer(ctx, projectID)
		if err != nil {
			log.Printf("[WARN] Failed to initialize Firestore syncer: %v", err)
		} else if fsSyncer != nil {
			log.Printf("[INFO] Initialized Real-Time Firestore Public Key Syncer for project: %s", projectID)
			if gcsStore, ok := store.(*keystore.GCSKeystore); ok {
				gcsStore.SetFirestoreSyncer(fsSyncer)
			} else if memStore, ok := store.(*keystore.EncryptedKeystore); ok {
				memStore.SetFirestoreSyncer(fsSyncer)
			}
			defer fsSyncer.Close()
		}
	}

	// Pre-provision or load Global Facility Key (Tenant ID "00000000000000")
	if _, err := store.GetTenantKey(ctx, "00000000000000", 1); err != nil {
		if _, genErr := store.GenerateTenantKey(ctx, "00000000000000", 1); genErr != nil {
			log.Printf("[WARN] Failed to initialize global facility key: %v", genErr)
		} else {
			log.Println("[INFO] Provisioned Global Facility Key (v1) in Keystore.")
		}
	} else {
		log.Println("[INFO] Global Facility Key (v1) loaded from persistent Keystore.")
	}

	// Initialize Deduplication & Bloom Filter Engine (Redis or In-Memory)
	dedupEngine := dedup.NewEngineFromEnv(ctx)

	// Initialize MCP Server
	mcpServer := mcp.NewServer(store, dedupEngine)

	// If Stdio mode requested, run MCP JSON-RPC Stdio loop directly
	if isStdio {
		if err := mcpServer.ServeStdio(); err != nil {
			os.Exit(1)
		}
		return
	}

	// Standard Cloud Run HTTP Server Mode
	log.Println("Starting Consteon Offline QR Generator & MCP Server for Cloud Run...")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mcpHTTPHandler := mcp.NewHTTPHandler(mcpServer)
	apiHandler := api.NewHandler(store, dedupEngine)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, apiHandler, mcpHTTPHandler, oidcAudience)

	// Wrap with CORS and Recovery middlewares
	rootHandler := api.RecoveryMiddleware(api.CORSMiddleware(mux))

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      rootHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown setup
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[READY] Server listening on port %s", port)
		log.Printf("[MCP] Model Context Protocol endpoints active at POST /mcp and GET /sse")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down server gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
	log.Println("Server stopped.")
}
