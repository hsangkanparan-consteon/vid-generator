package api

import (
	"net/http"

	"consteon.com/qr-generator/internal/mcp"
)

// RegisterRoutes registers all HTTP and MCP handlers onto the provided ServeMux.
func RegisterRoutes(mux *http.ServeMux, h *Handler, mcpHandler *mcp.HTTPHandler, expectedAudience string) {
	// Public Health Check
	mux.HandleFunc("GET /health", h.HealthCheck)
	mux.HandleFunc("GET /", h.HealthCheck)

	// Protected Endpoints
	authMiddleware := OIDCAuthMiddleware(expectedAudience)

	// REST API Minting Endpoints (Single)
	mux.Handle("POST /v1/qr/location", authMiddleware(http.HandlerFunc(h.MintLocation)))
	mux.Handle("POST /v1/qr/asset", authMiddleware(http.HandlerFunc(h.MintAsset)))
	mux.Handle("POST /v1/qr/user", authMiddleware(http.HandlerFunc(h.MintUser)))
	mux.Handle("POST /v1/qr/other", authMiddleware(http.HandlerFunc(h.MintOther)))

	// REST API Minting Endpoints (Batch)
	mux.Handle("POST /v1/qr/location/batch", authMiddleware(http.HandlerFunc(h.MintBatchLocation)))
	mux.Handle("POST /v1/qr/asset/batch", authMiddleware(http.HandlerFunc(h.MintBatchAsset)))
	mux.Handle("POST /v1/qr/user/batch", authMiddleware(http.HandlerFunc(h.MintBatchUser)))
	mux.Handle("POST /v1/qr/other/batch", authMiddleware(http.HandlerFunc(h.MintBatchOther)))

	// REST API Verification & Decoding
	mux.Handle("POST /v1/qr/decode", authMiddleware(http.HandlerFunc(h.DecodeQR)))

	// Key Management Endpoints
	mux.Handle("POST /v1/keys/generate", authMiddleware(http.HandlerFunc(h.GenerateTenantKey)))
	mux.Handle("GET /v1/public-keys", authMiddleware(http.HandlerFunc(h.GetPublicKey)))

	// Model Context Protocol (MCP) Endpoints
	if mcpHandler != nil {
		// Direct JSON-RPC 2.0 POST endpoint
		mux.Handle("POST /mcp", authMiddleware(http.HandlerFunc(mcpHandler.HandleMCPPost)))

		// SSE Transport Endpoints
		mux.Handle("GET /sse", authMiddleware(http.HandlerFunc(mcpHandler.HandleSSE)))
		mux.Handle("GET /mcp/sse", authMiddleware(http.HandlerFunc(mcpHandler.HandleSSE)))
		mux.Handle("POST /mcp/messages", authMiddleware(http.HandlerFunc(mcpHandler.HandleSSEMessage)))
	}
}
