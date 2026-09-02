package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"consteon.com/qr-generator/internal/keystore"
	"consteon.com/qr-generator/internal/kms"
)

func setupTestMCPServer(t *testing.T) (*Server, keystore.Keystore) {
	mockKMS, err := kms.NewMockKMSClient()
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}
	ks := keystore.NewEncryptedKeystore(mockKMS)
	s := NewServer(ks)
	return s, ks
}

func TestMCPInitialize(t *testing.T) {
	s, _ := setupTestMCPServer(t)
	ctx := context.Background()

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	resp := s.HandleRPC(ctx, req)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	initRes, ok := resp.Result.(InitializeResult)
	if !ok {
		t.Fatalf("expected InitializeResult, got %T", resp.Result)
	}

	if initRes.ProtocolVersion != "2024-11-05" {
		t.Errorf("expected protocolVersion 2024-11-05, got %s", initRes.ProtocolVersion)
	}
	if initRes.ServerInfo.Name != "consteon-qr-mcp-server" {
		t.Errorf("expected server name consteon-qr-mcp-server, got %s", initRes.ServerInfo.Name)
	}
}

func TestMCPToolsListAndCall(t *testing.T) {
	s, store := setupTestMCPServer(t)
	ctx := context.Background()

	tenantID := "10002000300040"
	keyRec, err := store.GenerateTenantKey(ctx, tenantID, 1)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// 1. tools/list
	listReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	listResp := s.HandleRPC(ctx, listReq)
	if listResp.Error != nil {
		t.Fatalf("tools/list error: %v", listResp.Error)
	}
	toolsRes := listResp.Result.(ListToolsResult)
	if len(toolsRes.Tools) < 7 {
		t.Fatalf("expected at least 7 tools, got %d", len(toolsRes.Tools))
	}

	// 2. tools/call: mint_asset_qr (with UID)
	argsMap := map[string]any{
		"tenant_id": tenantID,
		"unspsc":    "251015",
		"asset_uid": "CAR-2026-XYZ",
	}
	argsBytes, _ := json.Marshal(map[string]any{
		"name":      "mint_asset_qr",
		"arguments": argsMap,
	})

	callReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  argsBytes,
	}

	callResp := s.HandleRPC(ctx, callReq)
	if callResp.Error != nil {
		t.Fatalf("tools/call mint_asset_qr error: %v", callResp.Error)
	}

	callRes := callResp.Result.(CallToolResult)
	if callRes.IsError {
		t.Fatalf("callTool returned error: %s", callRes.Content[0].Text)
	}

	var mintedData map[string]any
	if err := json.Unmarshal([]byte(callRes.Content[0].Text), &mintedData); err != nil {
		t.Fatalf("failed to unmarshal tool output: %v", err)
	}

	fullURL := mintedData["full_url"].(string)

	// 3. tools/call: verify_qr
	verifyArgsBytes, _ := json.Marshal(map[string]any{
		"name": "verify_qr",
		"arguments": map[string]any{
			"url":        fullURL,
			"public_key": mintedData["token_base64url"], // wait, pubkey is separate
		},
	})

	verifyArgsBytes, _ = json.Marshal(map[string]any{
		"name": "verify_qr",
		"arguments": map[string]any{
			"url":         fullURL,
			"public_key":  mintedData["token_base64url"], // invalid pubkey test
			"key_version": 1,
		},
	})
	// Try with actual pub key hex
	pubHex := keyRec.PublicKey
	verifyArgsBytes, _ = json.Marshal(map[string]any{
		"name": "verify_qr",
		"arguments": map[string]any{
			"url":         fullURL,
			"public_key":  string(pubHex), // will be parsed
			"key_version": 1,
		},
	})

	verifyReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  verifyArgsBytes,
	}
	verifyResp := s.HandleRPC(ctx, verifyReq)
	if verifyResp.Error != nil {
		t.Fatalf("verify_qr error: %v", verifyResp.Error)
	}
}

func TestMCPResourcesAndPrompts(t *testing.T) {
	s, _ := setupTestMCPServer(t)
	ctx := context.Background()

	// 1. resources/list
	resListReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "resources/list",
	}
	resListResp := s.HandleRPC(ctx, resListReq)
	if resListResp.Error != nil {
		t.Fatalf("resources/list error: %v", resListResp.Error)
	}

	// 2. resources/read
	readParams, _ := json.Marshal(ReadResourceParams{URI: "autsorz://schemes"})
	readReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "resources/read",
		Params:  readParams,
	}
	readResp := s.HandleRPC(ctx, readReq)
	if readResp.Error != nil {
		t.Fatalf("resources/read error: %v", readResp.Error)
	}

	// 3. prompts/list
	promptListReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      7,
		Method:  "prompts/list",
	}
	promptListResp := s.HandleRPC(ctx, promptListReq)
	if promptListResp.Error != nil {
		t.Fatalf("prompts/list error: %v", promptListResp.Error)
	}

	// 4. prompts/get
	getPromptParams, _ := json.Marshal(GetPromptParams{
		Name:      "mint_asset_wizard",
		Arguments: map[string]string{"asset_type": "Dell Laptop"},
	})
	getPromptReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      8,
		Method:  "prompts/get",
		Params:  getPromptParams,
	}
	getPromptResp := s.HandleRPC(ctx, getPromptReq)
	if getPromptResp.Error != nil {
		t.Fatalf("prompts/get error: %v", getPromptResp.Error)
	}
}

func TestMCPHTTPHandler(t *testing.T) {
	s, _ := setupTestMCPServer(t)
	h := NewHTTPHandler(s)

	reqBody := `{"jsonrpc":"2.0","id":10,"method":"ping"}`
	httpReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleMCPPost(rec, httpReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var jsonResp JSONRPCResponse
	if err := json.NewDecoder(rec.Body).Decode(&jsonResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if jsonResp.ID != float64(10) {
		t.Errorf("expected ID 10, got %v", jsonResp.ID)
	}
}
