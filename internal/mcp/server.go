package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"consteon.com/qr-generator/internal/codec"
	"consteon.com/qr-generator/internal/crypto"
	"consteon.com/qr-generator/internal/dedup"
	"consteon.com/qr-generator/internal/keystore"
	"consteon.com/qr-generator/pkg/sheets"
	"consteon.com/qr-generator/pkg/verifier"
)

// Server implements the core Model Context Protocol (MCP) server logic.
type Server struct {
	keystore    keystore.Keystore
	verifier    *verifier.OfflineVerifier
	dedupEngine *dedup.Engine
}

// NewServer creates a new MCP Server instance.
func NewServer(ks keystore.Keystore, d ...*dedup.Engine) *Server {
	var de *dedup.Engine
	if len(d) > 0 && d[0] != nil {
		de = d[0]
	} else {
		de = dedup.NewEngine(nil)
	}
	return &Server{
		keystore:    ks,
		verifier:    verifier.NewOfflineVerifier(),
		dedupEngine: de,
	}
}

// HandleRPC processes a single JSON-RPC 2.0 MCP request and returns the response.
func (s *Server) HandleRPC(ctx context.Context, req JSONRPCRequest) JSONRPCResponse {
	// Notifications (e.g. notifications/initialized) do not expect a response
	if req.ID == nil && strings.HasPrefix(req.Method, "notifications/") {
		return JSONRPCResponse{}
	}

	res := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		res.Result = InitializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities: ServerCaps{
				Tools:     &ToolsServerCap{ListChanged: false},
				Resources: &ResourcesServerCap{Subscribe: false, ListChanged: false},
				Prompts:   &PromptsServerCap{ListChanged: false},
			},
			ServerInfo: Implementation{
				Name:    "consteon-qr-mcp-server",
				Version: "1.0.0",
			},
			Instructions: "Consteon QR Generator MCP Server provides tools to mint and verify high-security, compact Ed25519 asymmetric QR codes for Locations, Assets (UNSPSC), and Users (VID).",
		}

	case "ping":
		res.Result = map[string]any{}

	case "tools/list":
		res.Result = ListToolsResult{
			Tools: s.getToolDefinitions(),
		}

	case "tools/call":
		var params CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			res.Error = &JSONRPCError{
				Code:    ErrCodeInvalidParams,
				Message: "failed to parse callTool params: " + err.Error(),
			}
			return res
		}

		result, err := s.callTool(ctx, params.Name, params.Arguments)
		if err != nil {
			res.Result = CallToolResult{
				Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}
		} else {
			res.Result = result
		}

	case "resources/list":
		res.Result = ListResourcesResult{
			Resources: s.getResourceDefinitions(),
		}

	case "resources/read":
		var params ReadResourceParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			res.Error = &JSONRPCError{
				Code:    ErrCodeInvalidParams,
				Message: "failed to parse readResource params: " + err.Error(),
			}
			return res
		}

		content, err := s.readResource(params.URI)
		if err != nil {
			res.Error = &JSONRPCError{
				Code:    ErrCodeInternalError,
				Message: err.Error(),
			}
			return res
		}
		res.Result = ReadResourceResult{Contents: []ResourceContent{content}}

	case "prompts/list":
		res.Result = ListPromptsResult{
			Prompts: s.getPromptDefinitions(),
		}

	case "prompts/get":
		var params GetPromptParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			res.Error = &JSONRPCError{
				Code:    ErrCodeInvalidParams,
				Message: "failed to parse getPrompt params: " + err.Error(),
			}
			return res
		}

		promptRes, err := s.getPrompt(params.Name, params.Arguments)
		if err != nil {
			res.Error = &JSONRPCError{
				Code:    ErrCodeInternalError,
				Message: err.Error(),
			}
			return res
		}
		res.Result = promptRes

	default:
		res.Error = &JSONRPCError{
			Code:    ErrCodeMethodNotFound,
			Message: fmt.Sprintf("method '%s' not found", req.Method),
		}
	}

	return res
}

func (s *Server) getToolDefinitions() []Tool {
	return []Tool{
		{
			Name:        "mint_asset_qr",
			Description: "Mint an ultra-compact asymmetric Ed25519 QR Code for an Asset using UNSPSC classification (4 or 6 digits, e.g. '251015' for Passenger Cars, '432115' for Computers). Returns full URL, cell A2 token string ('3...'), and Google Sheets formula. Supports generic (69B) or specific (74B with UID).",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "14-digit numeric tenant ID (e.g. '10002000300040')",
					},
					"unspsc": {
						Type:        "string",
						Description: "4-digit or 6-digit UNSPSC commodity/class code (e.g. '251015' for passenger cars, '432115' for laptops/desktops, '401017' for ACs)",
					},
					"asset_uid": {
						Type:        "string",
						Description: "Optional Asset UID or serial number (e.g. 'CAR-2026-XYZ' or numeric '987654'). If omitted, mints a 69-byte generic category QR code.",
					},
					"key_version": {
						Type:        "number",
						Description: "Optional key version number (defaults to 1)",
						Default:     1,
					},
				},
				Required: []string{"tenant_id", "unspsc"},
			},
		},
		{
			Name:        "mint_location_qr",
			Description: "Mint an ultra-compact asymmetric Ed25519 QR Code for a physical Location (gates, rooms, toilets, guard stations). Returns full URL and Google Sheets formula.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "14-digit numeric tenant ID (e.g. '10002000300040' or '00000000000000' for Global Facility)",
					},
					"country_code": {
						Type:        "number",
						Description: "ISO 3166-1 numeric country code (e.g. 360 for Indonesia)",
						Default:     360,
					},
					"subtype": {
						Type:        "string",
						Description: "Location subtype ('portal', 'guard_station', 'room', 'toilet', 'gate', 'checkpoint')",
						Enum:        []string{"portal", "guard_station", "room", "toilet", "gate", "checkpoint"},
					},
					"location_uid": {
						Type:        "string",
						Description: "Optional unique Location UID number or string. If omitted, mints a 69-byte generic location QR.",
					},
					"key_version": {
						Type:        "number",
						Description: "Optional key version number (defaults to 1)",
						Default:     1,
					},
				},
				Required: []string{"tenant_id", "subtype"},
			},
		},
		{
			Name:        "mint_user_qr",
			Description: "Mint an asymmetric Ed25519 QR Code for an Employee / User badge (14-digit numeric VID).",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "14-digit numeric tenant ID (e.g. '10002000300040')",
					},
					"vid": {
						Type:        "string",
						Description: "14-digit numeric User VID (e.g. '12345678901234')",
					},
					"key_version": {
						Type:        "number",
						Description: "Optional key version number (defaults to 1)",
						Default:     1,
					},
				},
				Required: []string{"tenant_id", "vid"},
			},
		},
		{
			Name:        "mint_other_qr",
			Description: "Mint an asymmetric Ed25519 QR Code for IoT devices, smart meters, or custom process tracking.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "14-digit numeric tenant ID",
					},
					"subtype": {
						Type:        "number",
						Description: "Subtype byte identifier (e.g. 1 for IoT, 2 for Process)",
					},
					"entity_id": {
						Type:        "string",
						Description: "14-digit numeric entity ID",
					},
					"metadata": {
						Type:        "string",
						Description: "Hex-encoded or plain text metadata string",
					},
					"key_version": {
						Type:        "number",
						Description: "Optional key version number",
						Default:     1,
					},
				},
				Required: []string{"tenant_id", "subtype", "entity_id"},
			},
		},
		{
			Name:        "verify_and_decrypt_qr",
			Description: "Decrypt and verify any autsorz QR code URL ('https://autsorz/l/3...') or raw token string ('3...'). Automatically retrieves the tenant's public key, validates the Ed25519 signature, and unpacks the exact unencrypted Location ID, Asset ID (with UNSPSC title), or User VID.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"token": {
						Type:        "string",
						Description: "Full scanned QR URL (e.g. 'https://autsorz/l/3EQ...') or cell A2 token string ('3EQ...')",
					},
					"tenant_id": {
						Type:        "string",
						Description: "14-digit numeric tenant ID (defaults to '62000000000000')",
						Default:     "62000000000000",
					},
				},
				Required: []string{"token"},
			},
		},
		{
			Name:        "verify_qr",
			Description: "Verify an autsorz QR code URL ('https://autsorz/l/3...') or raw token string offline using an explicit Ed25519 public key. Validates signature and decodes all payload fields.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"url": {
						Type:        "string",
						Description: "Full scanned URL (e.g. 'https://autsorz/l/3IQED...') or cell A2 token string ('3IQED...')",
					},
					"public_key": {
						Type:        "string",
						Description: "32-byte Ed25519 Public Key in Hex (64 chars) or Base64/Base64URL (43 chars) format",
					},
					"key_version": {
						Type:        "number",
						Description: "Key version number associated with this public key (defaults to 1)",
						Default:     1,
					},
				},
				Required: []string{"url", "public_key"},
			},
		},
		{
			Name:        "generate_tenant_key",
			Description: "Generate a new Ed25519 asymmetric key pair for a 14-digit tenant. The private key is securely envelope-encrypted via Google Cloud KMS.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "14-digit numeric tenant ID (e.g. '10002000300040')",
					},
					"key_version": {
						Type:        "number",
						Description: "Key version to generate (defaults to 1)",
						Default:     1,
					},
				},
				Required: []string{"tenant_id"},
			},
		},
		{
			Name:        "get_public_key",
			Description: "Retrieve the Ed25519 Public Key for a tenant or global facility for mobile device distribution and offline verification.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "14-digit numeric tenant ID (or '00000000000000' for Global Facility)",
						Default:     "00000000000000",
					},
					"key_version": {
						Type:        "number",
						Description: "Key version number (defaults to 1)",
						Default:     1,
					},
				},
			},
		},
		// --- Batch Tools ---
		{
			Name:        "batch_mint_location_qr",
			Description: "Mint multiple Location QR codes in a single request. Each item can have its own subtype, country code, and optional location_uid. Returns an array of full URLs and QR formulas.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id":    {Type: "string", Description: "14-digit numeric tenant ID"},
					"country_code": {Type: "number", Description: "Default ISO 3166-1 numeric country code for all items (e.g. 360)"},
					"items": {
						Type:        "string",
						Description: "JSON array of location items. Each item: {\"subtype\": \"room\", \"location_uid\": \"101\", \"country_code\": 360 (optional)}",
					},
					"key_version": {Type: "number", Description: "Optional key version (defaults to 1)", Default: 1},
				},
				Required: []string{"tenant_id", "items"},
			},
		},
		{
			Name:        "batch_mint_asset_qr",
			Description: "Mint multiple Asset QR codes in a single request. Each item specifies a UNSPSC code and optional asset_uid. Returns an array of full URLs and QR formulas.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {Type: "string", Description: "14-digit numeric tenant ID"},
					"items": {
						Type:        "string",
						Description: "JSON array of asset items. Each item: {\"unspsc\": \"432115\", \"asset_uid\": \"LAPTOP-001\" (optional)}",
					},
					"key_version": {Type: "number", Description: "Optional key version (defaults to 1)", Default: 1},
				},
				Required: []string{"tenant_id", "items"},
			},
		},
		{
			Name:        "batch_mint_user_qr",
			Description: "Mint multiple User (employee badge) QR codes in a single request from a list of VIDs. Returns an array of full URLs and QR formulas.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {Type: "string", Description: "14-digit numeric tenant ID"},
					"vids": {
						Type:        "string",
						Description: "JSON array of 14-digit numeric VIDs (e.g. [\"12345678901234\", \"98765432109876\"])",
					},
					"key_version": {Type: "number", Description: "Optional key version (defaults to 1)", Default: 1},
				},
				Required: []string{"tenant_id", "vids"},
			},
		},
		{
			Name:        "batch_mint_other_qr",
			Description: "Mint multiple IoT/Other QR codes in a single request. Returns an array of full URLs and QR formulas.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {Type: "string", Description: "14-digit numeric tenant ID"},
					"items": {
						Type:        "string",
						Description: "JSON array of items. Each item: {\"subtype\": 1, \"entity_id\": \"00000000000001\", \"metadata\": \"optional\"}",
					},
					"key_version": {Type: "number", Description: "Optional key version (defaults to 1)", Default: 1},
				},
				Required: []string{"tenant_id", "items"},
			},
		},
	}
}

func (s *Server) callTool(ctx context.Context, name string, args map[string]any) (CallToolResult, error) {
	switch name {
	case "mint_asset_qr":
		tenantID := getString(args, "tenant_id")
		unspsc := getString(args, "unspsc")
		assetUIDRaw := getString(args, "asset_uid")
		keyVer := uint8(getInt(args, "key_version", 1))

		hasUID := false
		var raw16 []byte
		var assetUID uint64
		var unencID string

		trimmedUID := strings.TrimSpace(assetUIDRaw)
		if trimmedUID == "generate" || trimmedUID == "random" || trimmedUID == "auto" {
			raw16Arr, generatedUnenc, err := s.dedupEngine.GenerateUniqueAssetID(ctx, tenantID)
			if err != nil {
				return CallToolResult{}, fmt.Errorf("failed to generate unique asset_id: %w", err)
			}
			raw16 = raw16Arr[:]
			unencID = generatedUnenc
			hasUID = true
		} else if trimmedUID != "" {
			var is16 bool
			var err error
			raw16, assetUID, unencID, is16, err = codec.ParseAssetUIDString(trimmedUID)
			if err != nil {
				return CallToolResult{}, fmt.Errorf("invalid asset_uid: %w", err)
			}
			if is16 {
				isDup, err := s.dedupEngine.RegisterAssetID(ctx, tenantID, unencID)
				if err != nil {
					return CallToolResult{}, fmt.Errorf("dedup registration error: %w", err)
				}
				if isDup {
					return CallToolResult{}, fmt.Errorf("redundant asset_id: '%s' is already registered for this tenant", unencID)
				}
			}
			hasUID = true
		}

		header := codec.Header{
			Type:          codec.TypeAsset,
			FormatVersion: codec.FormatVersion1,
			KeyVersion:    keyVer,
		}
		headerBytes := codec.EncodeHeader(header)

		assetPayload := codec.AssetPayload{
			UNSPSC:        unspsc,
			HasUID:        hasUID,
			AssetUID:      assetUID,
			AssetIDRaw:    raw16,
			UnencryptedID: unencID,
		}

		payload, err := codec.EncodeAssetPayload(assetPayload)
		if err != nil {
			return CallToolResult{}, err
		}

		message := append(headerBytes[:], payload...)
		resp, err := s.signAndFormat(ctx, tenantID, keyVer, "asset", message)
		if err != nil {
			return CallToolResult{}, err
		}
		resp["unencrypted_id"] = unencID
		resp["asset_id"] = unencID
		resp["unspsc_title"] = codec.GetUNSPSCTitle(unspsc)

		jsonBytes, _ := json.MarshalIndent(resp, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "mint_location_qr":
		tenantID := getString(args, "tenant_id")
		if tenantID == "" {
			tenantID = "00000000000000"
		}
		country := uint16(getInt(args, "country_code", 360))
		subtype := getString(args, "subtype")
		locUIDRaw := getString(args, "location_uid")
		keyVer := uint8(getInt(args, "key_version", 1))

		hasUID := false
		var raw16 []byte
		var locUID uint64
		var unencID string

		trimmedUID := strings.TrimSpace(locUIDRaw)
		if trimmedUID == "generate" || trimmedUID == "random" || trimmedUID == "auto" {
			raw16Arr, generatedUnenc, err := s.dedupEngine.GenerateUniqueLocationID(ctx, tenantID)
			if err != nil {
				return CallToolResult{}, fmt.Errorf("failed to generate unique location_id: %w", err)
			}
			raw16 = raw16Arr[:]
			unencID = generatedUnenc
			hasUID = true
		} else if trimmedUID != "" {
			var is16 bool
			var err error
			raw16, locUID, unencID, is16, err = codec.ParseLocationUIDString(trimmedUID)
			if err != nil {
				return CallToolResult{}, fmt.Errorf("invalid location_uid: %w", err)
			}
			if is16 {
				isDup, err := s.dedupEngine.RegisterLocationID(ctx, tenantID, unencID)
				if err != nil {
					return CallToolResult{}, fmt.Errorf("dedup registration error: %w", err)
				}
				if isDup {
					return CallToolResult{}, fmt.Errorf("redundant location_id: '%s' is already registered for this tenant", unencID)
				}
			}
			hasUID = true
		}

		header := codec.Header{
			Type:          codec.TypeLocation,
			FormatVersion: codec.FormatVersion1,
			KeyVersion:    keyVer,
		}
		headerBytes := codec.EncodeHeader(header)

		locPayload := codec.LocationPayload{
			CountryCode:   country,
			Subtype:       codec.ParseLocationSubtype(subtype),
			HasUID:        hasUID,
			LocationUID:   locUID,
			LocationIDRaw: raw16,
			UnencryptedID: unencID,
		}

		payload := codec.EncodeLocationPayload(locPayload)
		message := append(headerBytes[:], payload...)
		resp, err := s.signAndFormat(ctx, tenantID, keyVer, "location", message)
		if err != nil {
			return CallToolResult{}, err
		}
		resp["unencrypted_id"] = unencID
		resp["location_id"] = unencID

		jsonBytes, _ := json.MarshalIndent(resp, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "mint_user_qr":
		tenantID := getString(args, "tenant_id")
		vid := getString(args, "vid")
		keyVer := uint8(getInt(args, "key_version", 1))

		header := codec.Header{
			Type:          codec.TypeUser,
			FormatVersion: codec.FormatVersion1,
			KeyVersion:    keyVer,
		}
		headerBytes := codec.EncodeHeader(header)

		payload, err := codec.EncodeUserPayload(codec.UserPayload{VID: vid})
		if err != nil {
			return CallToolResult{}, err
		}

		message := append(headerBytes[:], payload[:]...)
		resp, err := s.signAndFormat(ctx, tenantID, keyVer, "user", message)
		if err != nil {
			return CallToolResult{}, err
		}
		resp["unencrypted_id"] = vid

		jsonBytes, _ := json.MarshalIndent(resp, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "mint_other_qr":
		tenantID := getString(args, "tenant_id")
		subtype := uint8(getInt(args, "subtype", 1))
		entityID := getString(args, "entity_id")
		metadata := getString(args, "metadata")
		keyVer := uint8(getInt(args, "key_version", 1))

		header := codec.Header{
			Type:          codec.TypeOther,
			FormatVersion: codec.FormatVersion1,
			KeyVersion:    keyVer,
		}
		headerBytes := codec.EncodeHeader(header)

		var metaBytes []byte
		if strings.HasPrefix(metadata, "0x") || strings.HasPrefix(metadata, "0X") {
			metaBytes, _ = hex.DecodeString(metadata[2:])
		} else {
			metaBytes = []byte(metadata)
		}

		payload, err := codec.EncodeOtherPayload(codec.OtherPayload{
			Subtype:  subtype,
			EntityID: entityID,
			Metadata: metaBytes,
		})
		if err != nil {
			return CallToolResult{}, err
		}

		message := append(headerBytes[:], payload...)
		resp, err := s.signAndFormat(ctx, tenantID, keyVer, "other", message)
		if err != nil {
			return CallToolResult{}, err
		}
		resp["unencrypted_id"] = entityID

		jsonBytes, _ := json.MarshalIndent(resp, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "verify_and_decrypt_qr":
		tokenStr := strings.TrimSpace(getString(args, "token"))
		if tokenStr == "" {
			tokenStr = strings.TrimSpace(getString(args, "url"))
		}
		if tokenStr == "" {
			return CallToolResult{}, fmt.Errorf("token or url is required")
		}
		tenantID := getString(args, "tenant_id")
		if tenantID == "" {
			tenantID = "62000000000000"
		}

		rawToken := tokenStr
		if strings.HasPrefix(tokenStr, "http://") || strings.HasPrefix(tokenStr, "https://") {
			if idx := strings.LastIndex(tokenStr, "/"); idx != -1 {
				rawToken = tokenStr[idx+1:]
			}
		}
		if strings.HasPrefix(rawToken, "3") {
			rawToken = rawToken[1:]
		}

		rawBytes, err := crypto.DecodeBase64URL(rawToken)
		if err != nil || len(rawBytes) < codec.HeaderLength+codec.SignatureLength {
			// Try RFC 9285 Base45 decoding
			b45Bytes, b45Err := crypto.DecodeBase45(rawToken)
			if b45Err == nil && len(b45Bytes) >= codec.HeaderLength+codec.SignatureLength {
				rawBytes = b45Bytes
				err = nil
			} else if err != nil {
				return CallToolResult{Content: []ContentItem{{Type: "text", Text: fmt.Sprintf(`{"is_valid": false, "error": "invalid token encoding (expected Base64URL or RFC 9285 Base45): %v"}`, err)}}}, nil
			}
		}

		if len(rawBytes) < codec.HeaderLength+codec.SignatureLength {
			return CallToolResult{Content: []ContentItem{{Type: "text", Text: `{"is_valid": false, "error": "token too short"}`}}}, nil
		}

		header, err := codec.DecodeHeader(rawBytes[:codec.HeaderLength])
		if err != nil {
			return CallToolResult{Content: []ContentItem{{Type: "text", Text: fmt.Sprintf(`{"is_valid": false, "error": "invalid header: %v"}`, err)}}}, nil
		}

		sigBytes := rawBytes[len(rawBytes)-codec.SignatureLength:]
		messageBytes := rawBytes[:len(rawBytes)-codec.SignatureLength]
		payloadBytes := messageBytes[codec.HeaderLength:]

		rec, err := s.keystore.GetTenantKey(ctx, tenantID, header.KeyVersion)
		isValid := false
		if err == nil {
			isValid = crypto.Verify(rec.PublicKey, messageBytes, sigBytes)
		}

		resp := map[string]any{
			"is_valid":        isValid,
			"scheme":          3,
			"type":            header.Type.String(),
			"key_version":     header.KeyVersion,
			"tenant_id":       tenantID,
			"raw_bytes_count": len(rawBytes),
			"signature_hex":   hex.EncodeToString(sigBytes),
		}

		switch header.Type {
		case codec.TypeLocation:
			if locPayload, decErr := codec.DecodeLocationPayload(payloadBytes); decErr == nil {
				resp["country_code"] = locPayload.CountryCode
				resp["subtype"] = locPayload.Subtype.String()
				resp["location_uid"] = locPayload.LocationUID
				resp["unencrypted_id"] = locPayload.UnencryptedID
				resp["location_id"] = locPayload.UnencryptedID
				if locPayload.UnencryptedID != "" {
					isReg, _ := s.dedupEngine.IsLocationIDRegistered(ctx, tenantID, locPayload.UnencryptedID)
					resp["is_registered"] = isReg
				}
			}
		case codec.TypeAsset:
			if assetPayload, decErr := codec.DecodeAssetPayload(payloadBytes); decErr == nil {
				resp["unspsc"] = assetPayload.UNSPSC
				resp["unspsc_title"] = codec.GetUNSPSCTitle(assetPayload.UNSPSC)
				resp["asset_uid"] = assetPayload.AssetUID
				resp["unencrypted_id"] = assetPayload.UnencryptedID
				resp["asset_id"] = assetPayload.UnencryptedID
				if assetPayload.UnencryptedID != "" {
					isReg, _ := s.dedupEngine.IsAssetIDRegistered(ctx, tenantID, assetPayload.UnencryptedID)
					resp["is_registered"] = isReg
				}
			}
		case codec.TypeUser:
			if userPayload, decErr := codec.DecodeUserPayload(payloadBytes); decErr == nil {
				resp["vid"] = userPayload.VID
				resp["unencrypted_id"] = userPayload.VID
			}
		case codec.TypeOther:
			if otherPayload, decErr := codec.DecodeOtherPayload(payloadBytes); decErr == nil {
				resp["subtype"] = otherPayload.Subtype
				resp["entity_id"] = otherPayload.EntityID
				resp["metadata_hex"] = hex.EncodeToString(otherPayload.Metadata)
				resp["unencrypted_id"] = otherPayload.EntityID
			}
		}

		jsonBytes, _ := json.MarshalIndent(resp, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "verify_qr":
		rawURL := getString(args, "url")
		pubInput := getString(args, "public_key")
		keyVer := uint8(getInt(args, "key_version", 1))

		pubKeyBytes, err := parsePubKey(pubInput)
		if err != nil {
			return CallToolResult{}, err
		}

		v := verifier.NewOfflineVerifier()
		v.AddTenantKey(keyVer, pubKeyBytes)

		result, err := v.VerifyURL(rawURL)
		if err != nil {
			return CallToolResult{}, fmt.Errorf("verification failed: %w", err)
		}

		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "generate_tenant_key":
		tenantID := getString(args, "tenant_id")
		keyVer := uint8(getInt(args, "key_version", 1))

		rec, err := s.keystore.GenerateTenantKey(ctx, tenantID, keyVer)
		if err != nil {
			return CallToolResult{}, err
		}

		out := map[string]any{
			"tenant_id":            rec.TenantID,
			"key_version":          rec.KeyVersion,
			"public_key_hex":       hex.EncodeToString(rec.PublicKey),
			"public_key_base64url": crypto.EncodeBase64URL(rec.PublicKey),
			"created_at":           rec.CreatedAt.Format(time.RFC3339),
			"status":               "provisioned_in_cloud_kms",
		}
		jsonBytes, _ := json.MarshalIndent(out, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "get_public_key":
		tenantID := getString(args, "tenant_id")
		if tenantID == "" {
			tenantID = "00000000000000"
		}
		keyVer := uint8(getInt(args, "key_version", 1))

		rec, err := s.keystore.GetTenantKey(ctx, tenantID, keyVer)
		if err != nil {
			return CallToolResult{}, err
		}

		out := map[string]any{
			"tenant_id":            rec.TenantID,
			"key_version":          rec.KeyVersion,
			"public_key_hex":       hex.EncodeToString(rec.PublicKey),
			"public_key_base64url": crypto.EncodeBase64URL(rec.PublicKey),
			"created_at":           rec.CreatedAt.Format(time.RFC3339),
		}
		jsonBytes, _ := json.MarshalIndent(out, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "batch_mint_location_qr":
		tenantID := getString(args, "tenant_id")
		countryCode := uint16(getInt(args, "country_code", 360))
		keyVer := uint8(getInt(args, "key_version", 1))
		var items []struct {
			Subtype     string `json:"subtype"`
			LocationUID any    `json:"location_uid"`
			CountryCode uint16 `json:"country_code"`
		}
		if err := json.Unmarshal([]byte(getString(args, "items")), &items); err != nil {
			return CallToolResult{}, fmt.Errorf("invalid items JSON: %w", err)
		}
		results := make([]map[string]any, 0, len(items))
		for i, item := range items {
			cc := item.CountryCode
			if cc == 0 {
				cc = countryCode
			}
			rawUID := fmt.Sprintf("%v", item.LocationUID)
			if rawUID == "<nil>" {
				rawUID = ""
			}
			raw16, locUID, unencID, is16, err := codec.ParseLocationUIDString(rawUID)
			if err != nil {
				results = append(results, map[string]any{"index": i, "error": err.Error()})
				continue
			}
			header := codec.Header{Type: codec.TypeLocation, FormatVersion: codec.FormatVersion1, KeyVersion: keyVer}
			headerBytes := codec.EncodeHeader(header)
			payload := codec.LocationPayload{
				CountryCode:   cc,
				Subtype:       codec.ParseLocationSubtype(item.Subtype),
				HasUID:        true,
				LocationUID:   locUID,
				LocationIDRaw: raw16,
				UnencryptedID: unencID,
			}
			if !is16 && locUID == 0 && strings.TrimSpace(rawUID) == "" {
				payload.HasUID = false
			}
			payloadBytes := codec.EncodeLocationPayload(payload)
			out, err := s.signAndFormat(ctx, tenantID, keyVer, "location", append(headerBytes[:], payloadBytes...))
			if err != nil {
				results = append(results, map[string]any{"index": i, "error": err.Error()})
			} else {
				out["index"] = i
				out["unencrypted_id"] = unencID
				out["location_id"] = unencID
				results = append(results, out)
			}
		}
		jsonBytes, _ := json.MarshalIndent(map[string]any{"tenant_id": tenantID, "type": "location", "total_count": len(items), "results": results}, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "batch_mint_asset_qr":
		tenantID := getString(args, "tenant_id")
		keyVer := uint8(getInt(args, "key_version", 1))
		var items []struct {
			UNSPSC   string `json:"unspsc"`
			AssetUID any    `json:"asset_uid"`
		}
		if err := json.Unmarshal([]byte(getString(args, "items")), &items); err != nil {
			return CallToolResult{}, fmt.Errorf("invalid items JSON: %w", err)
		}
		results := make([]map[string]any, 0, len(items))
		for i, item := range items {
			rawUID := fmt.Sprintf("%v", item.AssetUID)
			if rawUID == "<nil>" {
				rawUID = ""
			}
			raw16, assetUID, unencID, is16, err := codec.ParseAssetUIDString(rawUID)
			if err != nil {
				results = append(results, map[string]any{"index": i, "error": err.Error()})
				continue
			}
			header := codec.Header{Type: codec.TypeAsset, FormatVersion: codec.FormatVersion1, KeyVersion: keyVer}
			headerBytes := codec.EncodeHeader(header)
			assetPayload := codec.AssetPayload{
				UNSPSC:        item.UNSPSC,
				HasUID:        true,
				AssetUID:      assetUID,
				AssetIDRaw:    raw16,
				UnencryptedID: unencID,
			}
			if !is16 && assetUID == 0 && strings.TrimSpace(rawUID) == "" {
				assetPayload.HasUID = false
			}
			payloadBytes, err := codec.EncodeAssetPayload(assetPayload)
			if err != nil {
				results = append(results, map[string]any{"index": i, "error": err.Error()})
				continue
			}
			out, err := s.signAndFormat(ctx, tenantID, keyVer, "asset", append(headerBytes[:], payloadBytes...))
			if err != nil {
				results = append(results, map[string]any{"index": i, "error": err.Error()})
			} else {
				out["index"] = i
				out["unencrypted_id"] = unencID
				out["asset_id"] = unencID
				out["unspsc_title"] = codec.GetUNSPSCTitle(item.UNSPSC)
				results = append(results, out)
			}
		}
		jsonBytes, _ := json.MarshalIndent(map[string]any{"tenant_id": tenantID, "type": "asset", "total_count": len(items), "results": results}, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "batch_mint_user_qr":
		tenantID := getString(args, "tenant_id")
		keyVer := uint8(getInt(args, "key_version", 1))
		var vids []string
		if err := json.Unmarshal([]byte(getString(args, "vids")), &vids); err != nil {
			return CallToolResult{}, fmt.Errorf("invalid vids JSON: %w", err)
		}
		results := make([]map[string]any, 0, len(vids))
		for i, vid := range vids {
			header := codec.Header{Type: codec.TypeUser, FormatVersion: codec.FormatVersion1, KeyVersion: keyVer}
			headerBytes := codec.EncodeHeader(header)
			payloadBytes, err := codec.EncodeUserPayload(codec.UserPayload{VID: vid})
			if err != nil {
				results = append(results, map[string]any{"index": i, "error": err.Error()})
				continue
			}
			out, err := s.signAndFormat(ctx, tenantID, keyVer, "user", append(headerBytes[:], payloadBytes[:]...))
			if err != nil {
				results = append(results, map[string]any{"index": i, "error": err.Error()})
			} else {
				out["index"] = i
				out["unencrypted_id"] = vid
				results = append(results, out)
			}
		}
		jsonBytes, _ := json.MarshalIndent(map[string]any{"tenant_id": tenantID, "type": "user", "total_count": len(vids), "results": results}, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	case "batch_mint_other_qr":
		tenantID := getString(args, "tenant_id")
		keyVer := uint8(getInt(args, "key_version", 1))
		var items []struct {
			Subtype  uint8  `json:"subtype"`
			EntityID string `json:"entity_id"`
			Metadata string `json:"metadata"`
		}
		if err := json.Unmarshal([]byte(getString(args, "items")), &items); err != nil {
			return CallToolResult{}, fmt.Errorf("invalid items JSON: %w", err)
		}
		results := make([]map[string]any, 0, len(items))
		for i, item := range items {
			header := codec.Header{Type: codec.TypeOther, FormatVersion: codec.FormatVersion1, KeyVersion: keyVer}
			headerBytes := codec.EncodeHeader(header)
			var metaBytes []byte
			if strings.HasPrefix(item.Metadata, "0x") {
				metaBytes, _ = hex.DecodeString(item.Metadata[2:])
			} else {
				metaBytes = []byte(item.Metadata)
			}
			payloadBytes, err := codec.EncodeOtherPayload(codec.OtherPayload{Subtype: item.Subtype, EntityID: item.EntityID, Metadata: metaBytes})
			if err != nil {
				results = append(results, map[string]any{"index": i, "error": err.Error()})
				continue
			}
			out, err := s.signAndFormat(ctx, tenantID, keyVer, "other", append(headerBytes[:], payloadBytes...))
			if err != nil {
				results = append(results, map[string]any{"index": i, "error": err.Error()})
			} else {
				out["index"] = i
				out["unencrypted_id"] = item.EntityID
				results = append(results, out)
			}
		}
		jsonBytes, _ := json.MarshalIndent(map[string]any{"tenant_id": tenantID, "type": "other", "total_count": len(items), "results": results}, "", "  ")
		return CallToolResult{Content: []ContentItem{{Type: "text", Text: string(jsonBytes)}}}, nil

	default:
		return CallToolResult{}, fmt.Errorf("unknown tool: %s", name)
	}
}

func (s *Server) signAndFormat(ctx context.Context, tenantID string, keyVer uint8, typeName string, message []byte) (map[string]any, error) {
	privKey, err := s.keystore.GetDecryptedPrivateKey(ctx, tenantID, keyVer)
	if err != nil {
		// Auto-provision: if key not found, generate and persist it now (Just-In-Time key generation)
		if _, genErr := s.keystore.GenerateTenantKey(ctx, tenantID, keyVer); genErr != nil {
			return nil, fmt.Errorf("tenant key not found and auto-provisioning failed: %w", genErr)
		}
		privKey, err = s.keystore.GetDecryptedPrivateKey(ctx, tenantID, keyVer)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve auto-provisioned key: %w", err)
		}
	}

	sig, err := crypto.Sign(privKey, message)
	if err != nil {
		return nil, err
	}

	fullToken := append(message, sig...)
	tokenB64 := crypto.EncodeBase64URL(fullToken)
	tokenWithScheme := sheets.SchemePrefix + tokenB64
	fullURL := sheets.BuildFullURL(tokenB64)
	tokenB45 := sheets.SchemePrefix + crypto.EncodeBase45(fullToken)

	return map[string]any{
		"tenant_id":            tenantID,
		"type":                 typeName,
		"key_version":          keyVer,
		"raw_bytes_count":      len(fullToken),
		"scheme":               "3 (Ed25519 Asymmetric)",
		"token_base64url":      tokenWithScheme,
		"token_base45":         tokenB45,
		"full_url":             fullURL,
		"google_sheets_cell":   sheets.BuildGoogleSheetsCellFormula("A2"),
		"qr_formula":           sheets.BuildGoogleSheetsFormula(fullURL),
		"qr_formula_version4":  fmt.Sprintf(`=IMAGE("https://api.qrserver.com/v1/create-qr-code/?size=310x310&ecc=L&margin=1&data=" & ENCODEURL("%s"))`, tokenB45),
		"target_qr_version":    "Version 4 (33x33 modules) with Base45 ECC L",
	}, nil
}

func (s *Server) getResourceDefinitions() []Resource {
	return []Resource{
		{
			URI:         "autsorz://schemes",
			Name:        "Autsorz QR Verification Schemes",
			Description: "Overview of Autsorz encryption and verification schemes (0=None, 1/2=Legacy, 3=Ed25519 Asymmetric).",
			MimeType:    "text/markdown",
		},
		{
			URI:         "autsorz://unspsc-reference",
			Name:        "Common UNSPSC Category Reference Table",
			Description: "Reference list of common 4-digit and 6-digit UNSPSC codes for assets.",
			MimeType:    "text/markdown",
		},
		{
			URI:         "autsorz://qr-sizing-guide",
			Name:        "QR Matrix Sizing & Optical Scanning Distance Guide",
			Description: "Physical dimensions, error correction tolerances, and phone scanning distances.",
			MimeType:    "text/markdown",
		},
	}
}

func (s *Server) readResource(uri string) (ResourceContent, error) {
	switch uri {
	case "autsorz://schemes":
		text := `# Autsorz Verification Scheme Definitions

- **Scheme 0**: Legacy Plaintext (no signature).
- **Scheme 1 & 2**: Legacy Proprietary Symmetric Encryption.
- **Scheme 3 (Standard)**: Asymmetric Digital Signatures via Ed25519 (RFC 8032).
  - Header: 2 Bytes [Type/Version (1B) | Key Version (1B)]
  - Payload: 3 to 8 Bytes (Location, Asset with UNSPSC, User VID)
  - Signature: 64 Bytes deterministic Ed25519 signature
  - Compliant with SOC 2 CC6.1 / ISO 27001 Control 8.24.`
		return ResourceContent{URI: uri, MimeType: "text/markdown", Text: text}, nil

	case "autsorz://unspsc-reference":
		text := `# UNSPSC Code Reference Table

| UNSPSC Code | Level | Description |
| :--- | :--- | :--- |
| **251015** | Class (6D) | Passenger Motor Vehicles (Cars, Sedans, SUVs) |
| **251016** | Class (6D) | Commercial & Cargo Motor Vehicles (Trucks, Vans) |
| **251017** | Class (6D) | Motorcycles & Scooters |
| **432115** | Class (6D) | Computers (Laptops, Desktops, Workstations) |
| **432121** | Class (6D) | Computer Printers & Scanners |
| **401017** | Class (6D) | Air Conditioners & Heat Pumps |
| **241118** | Class (6D) | Gas Cylinders & High-Pressure Storage Tanks |
| **261116** | Class (6D) | Power Generators (Diesel / Gas) |
| **481015** | Class (6D) | Cooking Stoves & Ovens |
| **2510** | Family (4D) | Motor Vehicles General |
| **4321** | Family (4D) | Computer Equipment General |
| **4010** | Family (4D) | Heating, Ventilation & AC (HVAC) General |`
		return ResourceContent{URI: uri, MimeType: "text/markdown", Text: text}, nil

	case "autsorz://qr-sizing-guide":
		text := `# QR Sizing & Optical Distance Guide

- **Target Matrix**: Version 6 (41x41 modules) with ecc=M (15% redundancy).
- **Sticker Size (10x10 cm)**:
  - Module width: 2.44 mm per dot.
  - Instant Capture Range: 0.3 m to 1.4 m (< 50 ms).
  - Maximum Reliable Distance (Low-End Smartphone): ~1.9 meters (6.2 ft).
  - Error Recovery: Tolerates up to 15% physical damage, dirt, or sunlight glare.`
		return ResourceContent{URI: uri, MimeType: "text/markdown", Text: text}, nil

	default:
		return ResourceContent{}, fmt.Errorf("resource not found: %s", uri)
	}
}

func (s *Server) getPromptDefinitions() []Prompt {
	return []Prompt{
		{
			Name:        "mint_asset_wizard",
			Description: "Guide the user to mint an asymmetric Asset QR code with UNSPSC category code and asset identification.",
			Arguments: []PromptArgument{
				{Name: "asset_type", Description: "Description of the physical asset (e.g. 'Toyota Corolla Company Car' or 'Dell Laptop')", Required: true},
				{Name: "tenant_id", Description: "14-digit numeric tenant ID", Required: false},
			},
		},
		{
			Name:        "audit_scanned_qr",
			Description: "Analyze, decode, and audit an autsorz QR code URL or scanned token string.",
			Arguments: []PromptArgument{
				{Name: "scanned_url", Description: "The raw scanned URL (https://autsorz/l/3...) or token string (3...)", Required: true},
				{Name: "public_key", Description: "Ed25519 public key of the issuer", Required: true},
			},
		},
	}
}

func (s *Server) getPrompt(name string, args map[string]string) (GetPromptResult, error) {
	switch name {
	case "mint_asset_wizard":
		assetType := args["asset_type"]
		tenantID := args["tenant_id"]
		if tenantID == "" {
			tenantID = "10002000300040"
		}
		msg := fmt.Sprintf("I need to mint an Asymmetric Ed25519 QR code for this asset: '%s'. Please identify the matching 4 or 6-digit UNSPSC code (e.g. 251015 for cars, 432115 for laptops) and use `mint_asset_qr` with tenant_id '%s' to generate the compact Version 6 QR code.", assetType, tenantID)
		return GetPromptResult{
			Description: "Mint Asset Wizard",
			Messages: []PromptMessage{
				{Role: "user", Content: ContentItem{Type: "text", Text: msg}},
			},
		}, nil

	case "audit_scanned_qr":
		url := args["scanned_url"]
		pubKey := args["public_key"]
		msg := fmt.Sprintf("Please verify this scanned QR URL '%s' offline using public key '%s' via the `verify_qr` tool, and report its scheme, type, UNSPSC / location data, and signature validity.", url, pubKey)
		return GetPromptResult{
			Description: "Audit Scanned QR Code",
			Messages: []PromptMessage{
				{Role: "user", Content: ContentItem{Type: "text", Text: msg}},
			},
		}, nil

	default:
		return GetPromptResult{}, fmt.Errorf("prompt not found: %s", name)
	}
}

// Helpers

func getString(args map[string]any, key string) string {
	if val, ok := args[key]; ok && val != nil {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return strconv.FormatUint(uint64(v), 10)
		case int:
			return strconv.Itoa(v)
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

func getInt(args map[string]any, key string, fallback int) int {
	if val, ok := args[key]; ok && val != nil {
		switch v := val.(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			if parsed, err := strconv.Atoi(v); err == nil {
				return parsed
			}
		}
	}
	return fallback
}

func parsePubKey(s string) ([]byte, error) {
	clean := strings.TrimSpace(s)
	if clean == "" {
		return nil, fmt.Errorf("empty public key")
	}
	if b, err := hex.DecodeString(clean); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := crypto.DecodeBase64URL(clean); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("invalid 32-byte public key (must be 64 hex characters or 43 base64 characters)")
}
