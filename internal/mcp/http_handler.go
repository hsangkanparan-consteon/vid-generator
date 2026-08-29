package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"consteon.com/vid-generator/internal/middleware"
)

type HTTPHandler struct {
	server *Server
}

func NewHTTPHandler(s *Server) *HTTPHandler {
	return &HTTPHandler{server: s}
}

func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/mcp", h.HandleMCP)
	mux.HandleFunc("/sse", h.HandleSSE)
}

func (h *HTTPHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "vid-generator",
		"version": "1.0.0",
	})
}

func (h *HTTPHandler) extractActor(r *http.Request) middleware.ActorInfo {
	identity := r.Header.Get("X-Goog-Authenticated-User-Email")
	if identity == "" {
		identity = r.Header.Get("X-Consumer-ID")
	}
	if identity == "" {
		identity = "internal-service-account"
	}

	role := r.Header.Get("X-Authenium-Role")
	if role == "" {
		role = string(middleware.RoleAdmin)
	}

	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}

	return middleware.ActorInfo{
		Identity:  identity,
		Role:      role,
		IPAddress: ip,
		UserAgent: r.UserAgent(),
	}
}

func (h *HTTPHandler) HandleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed (MCP requires POST)", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, nil, CodeParseError, "Failed to read request body")
		return
	}
	defer r.Body.Close()

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, nil, CodeParseError, "Invalid JSON format")
		return
	}

	actor := h.extractActor(r)
	ctx := r.Context()

	switch req.Method {
	case "initialize":
		res := InitializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities: ServerCapabilities{
				Tools: &ToolsCapability{ListChanged: true},
			},
			ServerInfo: Implementation{
				Name:    "consteon-vid-generator",
				Version: "1.0.0",
			},
			Instructions: "VID Generator MCP server for Authenium. Use generate_stock, allocate_vid, validate_vid, and get_stock_level.",
		}
		h.writeResult(w, req.ID, res)

	case "tools/list":
		tools := h.server.GetTools()
		h.writeResult(w, req.ID, map[string]interface{}{
			"tools": tools,
		})

	case "tools/call":
		var callParams CallToolParams
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			h.writeError(w, req.ID, CodeInvalidParams, "Invalid tool call parameters")
			return
		}

		result, err := h.server.CallTool(ctx, actor, callParams)
		if err != nil {
			h.writeError(w, req.ID, CodeInternalError, err.Error())
			return
		}
		h.writeResult(w, req.ID, result)

	case "ping":
		h.writeResult(w, req.ID, map[string]string{"status": "pong"})

	default:
		h.writeError(w, req.ID, CodeMethodNotFound, fmt.Sprintf("Unknown method: %s", req.Method))
	}
}

func (h *HTTPHandler) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	endpointURL := fmt.Sprintf("https://%s/mcp", r.Host)
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpointURL)
	flusher.Flush()

	<-r.Context().Done()
}

func (h *HTTPHandler) writeResult(w http.ResponseWriter, id interface{}, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	json.NewEncoder(w).Encode(resp)
}

func (h *HTTPHandler) writeError(w http.ResponseWriter, id interface{}, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: msg,
		},
	}
	json.NewEncoder(w).Encode(resp)
}
