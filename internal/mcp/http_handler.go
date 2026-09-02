package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// HTTPHandler exposes the MCP Server over HTTP (both direct JSON-RPC and SSE streams).
type HTTPHandler struct {
	server   *Server
	sessions sync.Map // sessionID -> chan JSONRPCResponse
}

// NewHTTPHandler creates an HTTPHandler for the MCP server.
func NewHTTPHandler(s *Server) *HTTPHandler {
	return &HTTPHandler{
		server: s,
	}
}

// HandleMCPPost handles direct JSON-RPC 2.0 POST requests to /mcp.
func (h *HTTPHandler) HandleMCPPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed (use POST)", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    ErrCodeParseError,
				Message: "invalid JSON-RPC 2.0 payload: " + err.Error(),
			},
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp := h.server.HandleRPC(r.Context(), req)
	writeJSON(w, http.StatusOK, resp)
}

// HandleSSE handles SSE connection on /sse or /mcp/sse.
func (h *HTTPHandler) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Generate unique session ID
	sessionBytes := make([]byte, 16)
	_, _ = rand.Read(sessionBytes)
	sessionID := hex.EncodeToString(sessionBytes)

	msgChan := make(chan JSONRPCResponse, 32)
	h.sessions.Store(sessionID, msgChan)
	defer func() {
		h.sessions.Delete(sessionID)
		close(msgChan)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Send endpoint event with session ID
	endpointURL := fmt.Sprintf("/mcp/messages?sessionId=%s", sessionID)
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpointURL)
	flusher.Flush()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case msg, ok := <-msgChan:
			if !ok {
				return
			}
			msgData, _ := json.Marshal(msg)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(msgData))
			flusher.Flush()
		}
	}
}

// HandleSSEMessage handles client messages posted to /mcp/messages?sessionId=...
func (h *HTTPHandler) HandleSSEMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		http.Error(w, "missing sessionId parameter", http.StatusBadRequest)
		return
	}

	val, exists := h.sessions.Load(sessionID)
	if !exists {
		http.Error(w, "session not found or expired", http.StatusNotFound)
		return
	}
	msgChan := val.(chan JSONRPCResponse)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON-RPC: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Process message in background and send response to SSE channel
	go func() {
		resp := h.server.HandleRPC(r.Context(), req)
		if resp.ID != nil || resp.Error != nil {
			select {
			case msgChan <- resp:
			default:
			}
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
}

func writeJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}
