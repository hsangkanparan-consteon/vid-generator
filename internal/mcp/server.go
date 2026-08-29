package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"consteon.com/vid-generator/internal/db"
	"consteon.com/vid-generator/internal/middleware"
	"consteon.com/vid-generator/internal/vid"
)

type Server struct {
	generator  *vid.Generator
	validator  *vid.Validator
	repo       *db.Repository
	audit      *middleware.AuditLogger
	authorizer *middleware.Authorizer
}

func NewServer(gen *vid.Generator, val *vid.Validator, repo *db.Repository, audit *middleware.AuditLogger, auth *middleware.Authorizer) *Server {
	return &Server{
		generator:  gen,
		validator:  val,
		repo:       repo,
		audit:      audit,
		authorizer: auth,
	}
}

func (s *Server) GetTools() []Tool {
	return []Tool{
		{
			Name:        "generate_stock",
			Description: "Batch-generate new unique 14-digit VIDs and populate available stock in Firestore for a country.",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"country_code": {
						Type:        "string",
						Description: "Country or system code: '62' (Indonesia), '1' (USA), '91' (India), '0' (System), '424' (System Core).",
						Enum:        []string{"62", "1", "91", "0", "424", "61"},
					},
					"count": {
						Type:        "integer",
						Description: "Number of VIDs to generate and store in stock (1 to 10,000).",
					},
				},
				Required: []string{"country_code", "count"},
			},
		},
		{
			Name:        "allocate_vid",
			Description: "Atomically claim and retrieve available VIDs from stock for a target country.",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"country_code": {
						Type:        "string",
						Description: "Country code to allocate VIDs from.",
					},
					"count": {
						Type:        "integer",
						Description: "Number of VIDs to claim (default 1, max 1000).",
					},
					"requester": {
						Type:        "string",
						Description: "Identifier of the requesting entity, service, or tenant.",
					},
				},
				Required: []string{"country_code"},
			},
		},
		{
			Name:        "validate_vid",
			Description: "Mathematically validates a 14-digit VID checksum, extracts address/cluster/position, and checks DB status.",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"vid": {
						Type:        "string",
						Description: "14-digit numeric VID to validate.",
					},
				},
				Required: []string{"vid"},
			},
		},
		{
			Name:        "get_vid_by_address",
			Description: "Looks up a VID and its lifecycle status by its 12-digit numeric address.",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"address": {
						Type:        "string",
						Description: "Numeric address string (up to 12 digits).",
					},
				},
				Required: []string{"address"},
			},
		},
		{
			Name:        "import_vids",
			Description: "Bulk imports a list of existing 14-digit VIDs into Firestore (marked as 'in_use'). Duplicates are automatically skipped.",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"vids": {
						Type:        "array",
						Description: "Array of 14-digit VID strings to import.",
					},
				},
				Required: []string{"vids"},
			},
		},
		{
			Name:        "get_stock_level",
			Description: "Returns inventory levels (available, allocated, in_use, revoked) for a country's VID stock.",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"country_code": {
						Type:        "string",
						Description: "Country code to check stock for (e.g. '62').",
					},
				},
				Required: []string{"country_code"},
			},
		},
		{
			Name:        "revoke_vid",
			Description: "Permanently revokes a VID. The record and address are permanently preserved to prevent reuse.",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"vid": {
						Type:        "string",
						Description: "14-digit VID to revoke.",
					},
					"reason": {
						Type:        "string",
						Description: "Reason for revocation.",
					},
				},
				Required: []string{"vid", "reason"},
			},
		},
	}
}

func (s *Server) CallTool(ctx context.Context, actor middleware.ActorInfo, params CallToolParams) (*CallToolResult, error) {
	start := time.Now()
	toolName := params.Name

	if err := s.authorizer.Authorize(actor.Role, toolName); err != nil {
		s.audit.Log(middleware.AuditDetail{
			EventType:       "SECURITY_ALERT",
			Action:          toolName,
			Result:          "DENIED",
			Actor:           actor,
			ExecutionTimeMs: time.Since(start).Milliseconds(),
			ErrorMessage:    err.Error(),
		})
		return &CallToolResult{
			Content: []Content{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		}, nil
	}

	var resData interface{}
	var execErr error

	switch toolName {
	case "generate_stock":
		resData, execErr = s.handleGenerateStock(ctx, params.Arguments)
	case "allocate_vid":
		resData, execErr = s.handleAllocateVID(ctx, params.Arguments, actor.Identity)
	case "validate_vid":
		resData, execErr = s.handleValidateVID(ctx, params.Arguments)
	case "get_vid_by_address":
		resData, execErr = s.handleGetByAddress(ctx, params.Arguments)
	case "import_vids":
		resData, execErr = s.handleImportVIDs(ctx, params.Arguments)
	case "get_stock_level":
		resData, execErr = s.handleGetStockLevel(ctx, params.Arguments)
	case "revoke_vid":
		resData, execErr = s.handleRevokeVID(ctx, params.Arguments)
	default:
		execErr = fmt.Errorf("unknown tool: %s", toolName)
	}

	execDuration := time.Since(start).Milliseconds()

	auditResult := "SUCCESS"
	errMsg := ""
	if execErr != nil {
		auditResult = "ERROR"
		errMsg = execErr.Error()
	}

	s.audit.Log(middleware.AuditDetail{
		EventType:       "AUDIT_EVENT",
		Action:          toolName,
		Result:          auditResult,
		Actor:           actor,
		ExecutionTimeMs: execDuration,
		Metadata:        resData,
		ErrorMessage:    errMsg,
	})

	if execErr != nil {
		return &CallToolResult{
			Content: []Content{{Type: "text", Text: fmt.Sprintf("Error: %v", execErr)}},
			IsError: true,
		}, nil
	}

	jsonBytes, err := json.MarshalIndent(resData, "", "  ")
	if err != nil {
		return nil, err
	}

	return &CallToolResult{
		Content: []Content{{Type: "text", Text: string(jsonBytes)}},
		IsError: false,
	}, nil
}

func (s *Server) handleGenerateStock(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	countryCode, ok := args["country_code"].(string)
	if !ok || countryCode == "" {
		return nil, fmt.Errorf("country_code is required")
	}

	countVal, ok := args["count"].(float64)
	if !ok || countVal <= 0 {
		return nil, fmt.Errorf("count must be a positive integer")
	}
	count := int(countVal)

	batchRes, err := s.generator.GenerateBatch(countryCode, count)
	if err != nil {
		return nil, fmt.Errorf("generation failed: %w", err)
	}

	inserted, duplicates, err := s.repo.CreateStockBatch(ctx, batchRes.VIDs, db.StatusAvailable)
	if err != nil {
		return nil, fmt.Errorf("failed to save to database: %w", err)
	}

	return map[string]interface{}{
		"country":         countryCode,
		"requested":       count,
		"inserted":        inserted,
		"duplicates":      duplicates,
		"total_attempts":  batchRes.TotalAttempts,
		"hit_rate_pct":    fmt.Sprintf("%.2f%%", batchRes.HitRate),
		"duration_ms":     batchRes.DurationMs,
		"status":          "COMPLETED",
	}, nil
}

func (s *Server) handleAllocateVID(ctx context.Context, args map[string]interface{}, callerID string) (interface{}, error) {
	countryCode, ok := args["country_code"].(string)
	if !ok || countryCode == "" {
		return nil, fmt.Errorf("country_code is required")
	}

	count := 1
	if countVal, ok := args["count"].(float64); ok && countVal > 0 {
		count = int(countVal)
	}

	requester := callerID
	if reqVal, ok := args["requester"].(string); ok && reqVal != "" {
		requester = reqVal
	}

	docs, err := s.repo.AllocateVIDsAtomic(ctx, countryCode, count, requester)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"country":   countryCode,
		"allocated": len(docs),
		"vids":      docs,
	}, nil
}

func (s *Server) handleValidateVID(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	vidStr, ok := args["vid"].(string)
	if !ok || vidStr == "" {
		return nil, fmt.Errorf("vid parameter is required")
	}

	mathRes := s.validator.Validate(vidStr)
	if !mathRes.Valid {
		return mathRes, nil
	}

	doc, err := s.repo.GetByVID(ctx, vidStr)
	if err != nil {
		return nil, err
	}

	dbStatus := "not_in_database"
	if doc != nil {
		dbStatus = string(doc.Status)
	}

	return map[string]interface{}{
		"valid":          mathRes.Valid,
		"vid":            mathRes.VID,
		"address":        mathRes.Address.Address,
		"cluster":        mathRes.Address.Cluster,
		"position":       mathRes.Address.Position,
		"country_code":   mathRes.CountryCode,
		"country_name":   mathRes.CountryName,
		"checksum_valid": mathRes.ChecksumValid,
		"db_status":      dbStatus,
		"record":         doc,
	}, nil
}

func (s *Server) handleGetByAddress(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	addrStr, ok := args["address"].(string)
	if !ok || addrStr == "" {
		return nil, fmt.Errorf("address parameter is required")
	}

	addrVal, err := strconv.ParseInt(addrStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid numeric address: %w", err)
	}

	doc, err := s.repo.GetByAddress(ctx, addrVal)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return map[string]interface{}{
			"exists":  false,
			"address": addrVal,
		}, nil
	}

	return map[string]interface{}{
		"exists":  true,
		"address": addrVal,
		"record":  doc,
	}, nil
}

func (s *Server) handleImportVIDs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	rawVIDs, ok := args["vids"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("vids array is required")
	}

	var candidates []*vid.GeneratedVID
	invalidCount := 0

	for _, v := range rawVIDs {
		str, ok := v.(string)
		if !ok {
			invalidCount++
			continue
		}

		res := s.validator.Validate(str)
		if !res.Valid {
			invalidCount++
			continue
		}

		candidates = append(candidates, &vid.GeneratedVID{
			VID:      res.VID,
			Address:  *res.Address,
			Country:  res.CountryCode,
			Attempts: 1,
		})
	}

	inserted, duplicates, err := s.repo.CreateStockBatch(ctx, candidates, db.StatusInUse)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_provided": len(rawVIDs),
		"imported":       inserted,
		"duplicates":     duplicates,
		"invalid":        invalidCount,
	}, nil
}

func (s *Server) handleGetStockLevel(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	countryCode, _ := args["country_code"].(string)
	if countryCode == "" {
		countryCode = "62"
	}

	stats, err := s.repo.GetStockStats(ctx, countryCode)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (s *Server) handleRevokeVID(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	vidStr, ok := args["vid"].(string)
	if !ok || vidStr == "" {
		return nil, fmt.Errorf("vid parameter is required")
	}

	reason, _ := args["reason"].(string)
	if reason == "" {
		reason = "administrative revocation"
	}

	doc, err := s.repo.RevokeVID(ctx, vidStr, reason)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"revoked": true,
		"vid":     vidStr,
		"record":  doc,
	}, nil
}
