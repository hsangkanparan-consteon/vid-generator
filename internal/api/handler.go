package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"consteon.com/qr-generator/internal/codec"
	"consteon.com/qr-generator/internal/crypto"
	"consteon.com/qr-generator/internal/dedup"
	"consteon.com/qr-generator/internal/keystore"
	"consteon.com/qr-generator/pkg/sheets"
)

// Handler manages HTTP API requests for minting and verifying QR tokens.
type Handler struct {
	keystore    keystore.Keystore
	dedupEngine *dedup.Engine
}

// NewHandler creates a Handler with the given Keystore and DedupEngine.
func NewHandler(ks keystore.Keystore, d ...*dedup.Engine) *Handler {
	var de *dedup.Engine
	if len(d) > 0 && d[0] != nil {
		de = d[0]
	} else {
		de = dedup.NewEngine(nil)
	}
	return &Handler{keystore: ks, dedupEngine: de}
}

// SetDedupEngine sets the deduplication engine.
func (h *Handler) SetDedupEngine(d *dedup.Engine) {
	if d != nil {
		h.dedupEngine = d
	}
}

// --- Request / Response Models ---

type MintLocationRequest struct {
	TenantID    string `json:"tenant_id"`              // 14-digit numeric string (e.g. "10002000300040" or "00000000000000" for Global)
	KeyVersion  uint8  `json:"key_version,omitempty"`  // defaults to 1
	CountryCode uint16 `json:"country_code"`          // ISO 3166-1 numeric, e.g. 360
	Subtype     string `json:"subtype"`               // "portal", "guard_station", "room", "toilet", "gate", "checkpoint"
	LocationUID any    `json:"location_uid,omitempty"` // numeric, string, or omitted (if omitted/empty: generic 69B location QR)
}

type MintAssetRequest struct {
	TenantID   string `json:"tenant_id"`             // 14-digit numeric tenant ID
	KeyVersion uint8  `json:"key_version,omitempty"` // defaults to 1
	UNSPSC     string `json:"unspsc"`                // 4-digit or 6-digit UNSPSC code (e.g. "251015" or "432115")
	AssetUID   any    `json:"asset_uid,omitempty"`   // numeric, string (e.g. "CAR-2026-XYZ"), or omitted (if omitted/empty: generic 69B asset QR)
}

type MintUserRequest struct {
	TenantID   string `json:"tenant_id"`             // 14-digit numeric tenant ID
	KeyVersion uint8  `json:"key_version,omitempty"` // defaults to 1
	VID        string `json:"vid"`                   // 14-digit numeric VID
}

type MintOtherRequest struct {
	TenantID   string `json:"tenant_id"`
	KeyVersion uint8  `json:"key_version,omitempty"`
	Subtype    uint8  `json:"subtype"`
	EntityID   string `json:"entity_id"` // 14-digit numeric string
	Metadata   string `json:"metadata"`  // hex or string metadata
}

type MintResponse struct {
	TenantID          string `json:"tenant_id"`
	Type              string `json:"type"`
	KeyVersion        uint8  `json:"key_version"`
	UnencryptedID     string `json:"unencrypted_id,omitempty"`
	RawBytesCount     int    `json:"raw_bytes_count"`
	TokenBase64URL    string `json:"token_base64url"`
	TokenBase45       string `json:"token_base45,omitempty"`
	FullURL           string `json:"full_url"`
	QRFormula         string `json:"qr_formula"`
	QRFormulaVersion4 string `json:"qr_formula_version4,omitempty"`
	QRFormulaCellA2   string `json:"qr_formula_cell_a2"`
}

// --- Batch Request / Response Models ---

type BatchLocationItem struct {
	LocationUID any    `json:"location_uid,omitempty"` // optional
	Subtype     string `json:"subtype"`
	CountryCode uint16 `json:"country_code,omitempty"` // override per item; falls back to batch-level
}

type BatchAssetItem struct {
	AssetUID any    `json:"asset_uid,omitempty"` // optional
	UNSPSC   string `json:"unspsc"`
}

type MintBatchLocationRequest struct {
	TenantID    string              `json:"tenant_id"`
	KeyVersion  uint8               `json:"key_version,omitempty"`
	CountryCode uint16              `json:"country_code"` // default for all items unless overridden
	Items       []BatchLocationItem `json:"items"`
}

type MintBatchAssetRequest struct {
	TenantID   string           `json:"tenant_id"`
	KeyVersion uint8            `json:"key_version,omitempty"`
	Items      []BatchAssetItem `json:"items"`
}

type MintBatchUserRequest struct {
	TenantID   string   `json:"tenant_id"`
	KeyVersion uint8    `json:"key_version,omitempty"`
	VIDs       []string `json:"vids"` // list of 14-digit numeric VIDs
}

type BatchOtherItem struct {
	Subtype  uint8  `json:"subtype"`
	EntityID string `json:"entity_id"`
	Metadata string `json:"metadata"`
}

type MintBatchOtherRequest struct {
	TenantID   string           `json:"tenant_id"`
	KeyVersion uint8            `json:"key_version,omitempty"`
	Items      []BatchOtherItem `json:"items"`
}

type BatchMintResult struct {
	Index           int    `json:"index"`
	UnencryptedID   string `json:"unencrypted_id,omitempty"`
	TokenBase64URL  string `json:"token_base64url"`
	TokenBase45     string `json:"token_base45,omitempty"`
	FullURL         string `json:"full_url"`
	QRFormula       string `json:"qr_formula"`
	QRFormulaBase45 string `json:"qr_formula_base45,omitempty"`
	Error           string `json:"error,omitempty"`
}

type BatchMintResponse struct {
	TenantID     string            `json:"tenant_id"`
	Type         string            `json:"type"`
	KeyVersion   uint8             `json:"key_version"`
	TotalCount   int               `json:"total_count"`
	SuccessCount int               `json:"success_count"`
	ErrorCount   int               `json:"error_count"`
	Results      []BatchMintResult `json:"results"`
}

type DecodeQRRequest struct {
	Token    string `json:"token"`              // full URL (e.g. "https://autsorz/l/3EQ...") or raw token ("3EQ...")
	TenantID string `json:"tenant_id,omitempty"` // optional override; if empty, uses default or looks up
}

type DecodeQRResponse struct {
	IsValid       bool   `json:"is_valid"`
	IsRegistered  bool   `json:"is_registered,omitempty"`
	Scheme        int    `json:"scheme"`
	Type          string `json:"type"`
	KeyVersion    uint8  `json:"key_version"`
	TenantID      string `json:"tenant_id,omitempty"`
	RawBytesCount int    `json:"raw_bytes_count"`
	UnencryptedID string `json:"unencrypted_id,omitempty"`

	// Type 1 Location fields
	CountryCode uint16 `json:"country_code,omitempty"`
	Subtype     string `json:"subtype,omitempty"`
	LocationID  string `json:"location_id,omitempty"`
	LocationUID uint64 `json:"location_uid,omitempty"`

	// Type 2 Asset fields
	UNSPSC      string `json:"unspsc,omitempty"`
	UNSPSCTitle string `json:"unspsc_title,omitempty"`
	AssetID     string `json:"asset_id,omitempty"`
	AssetUID    uint64 `json:"asset_uid,omitempty"`

	// Type 3 User fields
	VID string `json:"vid,omitempty"`

	// Type 4 Other fields
	OtherSubtype uint8  `json:"other_subtype,omitempty"`
	EntityID     string `json:"entity_id,omitempty"`
	MetadataHex  string `json:"metadata_hex,omitempty"`

	// Cryptographic Proof
	SignatureHex string `json:"signature_hex"`
	Error        string `json:"error,omitempty"`
}

type GenerateKeyRequest struct {
	TenantID   string `json:"tenant_id"`
	KeyVersion uint8  `json:"key_version,omitempty"`
}

type GenerateKeyResponse struct {
	TenantID     string `json:"tenant_id"`
	KeyVersion   uint8  `json:"key_version"`
	PublicKeyHex string `json:"public_key_hex"`
	PublicKeyB64 string `json:"public_key_base64url"`
	CreatedAt    string `json:"created_at"`
}

// --- Handler Methods ---

// HealthCheck provides standard Cloud Run liveness probe.
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "healthy",
		"service": "consteon-qr-generator",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// MintLocation handles Type 1 Location QR generation.
func (h *Handler) MintLocation(w http.ResponseWriter, r *http.Request) {
	var req MintLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}

	if req.TenantID == "" {
		req.TenantID = "00000000000000" // Default to Global
	}
	if req.KeyVersion == 0 {
		req.KeyVersion = 1
	}

	rawUIDStr := toString(req.LocationUID)
	hasUID := false
	var raw16 []byte
	var locUID uint64
	var unencID string

	trimmedUID := strings.TrimSpace(rawUIDStr)
	if trimmedUID == "generate" || trimmedUID == "random" || trimmedUID == "auto" {
		raw16Arr, generatedUnenc, err := h.dedupEngine.GenerateUniqueLocationID(r.Context(), req.TenantID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to generate unique location_id: "+err.Error())
			return
		}
		raw16 = raw16Arr[:]
		unencID = generatedUnenc
		hasUID = true
	} else if trimmedUID != "" {
		var is16 bool
		var err error
		raw16, locUID, unencID, is16, err = codec.ParseLocationUIDString(trimmedUID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid location_uid: "+err.Error())
			return
		}
		if is16 {
			isDup, err := h.dedupEngine.RegisterLocationID(r.Context(), req.TenantID, unencID)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "dedup registration error: "+err.Error())
				return
			}
			if isDup {
				writeJSONError(w, http.StatusConflict, fmt.Sprintf("redundant location_id: '%s' is already registered for this tenant", unencID))
				return
			}
		}
		hasUID = true
	}

	header := codec.Header{
		Type:          codec.TypeLocation,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    req.KeyVersion,
	}
	headerBytes := codec.EncodeHeader(header)

	locPayload := codec.LocationPayload{
		CountryCode:   req.CountryCode,
		Subtype:       codec.ParseLocationSubtype(req.Subtype),
		HasUID:        hasUID,
		LocationUID:   locUID,
		LocationIDRaw: raw16,
		UnencryptedID: unencID,
	}
	payloadBytes := codec.EncodeLocationPayload(locPayload)

	// Message to sign = Header (2B) + Payload
	message := append(headerBytes[:], payloadBytes...)

	resp, err := h.signAndBuildResponse(r.Context(), req.TenantID, req.KeyVersion, "location", message)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp.UnencryptedID = unencID

	writeJSON(w, http.StatusOK, resp)
}

// MintAsset handles Type 2 Asset QR generation with UNSPSC (up to 6 digits) and optional Asset UID.
func (h *Handler) MintAsset(w http.ResponseWriter, r *http.Request) {
	var req MintAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}

	if req.TenantID == "" {
		writeJSONError(w, http.StatusBadRequest, "tenant_id is required for Asset QRs")
		return
	}
	if req.KeyVersion == 0 {
		req.KeyVersion = 1
	}

	rawUIDStr := toString(req.AssetUID)
	hasUID := false
	var raw16 []byte
	var assetUID uint64
	var unencID string

	trimmedUID := strings.TrimSpace(rawUIDStr)
	if trimmedUID == "generate" || trimmedUID == "random" || trimmedUID == "auto" {
		raw16Arr, generatedUnenc, err := h.dedupEngine.GenerateUniqueAssetID(r.Context(), req.TenantID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to generate unique asset_id: "+err.Error())
			return
		}
		raw16 = raw16Arr[:]
		unencID = generatedUnenc
		hasUID = true
	} else if trimmedUID != "" {
		var is16 bool
		var err error
		raw16, assetUID, unencID, is16, err = codec.ParseAssetUIDString(trimmedUID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid asset_uid: "+err.Error())
			return
		}
		if is16 {
			isDup, err := h.dedupEngine.RegisterAssetID(r.Context(), req.TenantID, unencID)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "dedup registration error: "+err.Error())
				return
			}
			if isDup {
				writeJSONError(w, http.StatusConflict, fmt.Sprintf("redundant asset_id: '%s' is already registered for this tenant", unencID))
				return
			}
		}
		hasUID = true
	}

	header := codec.Header{
		Type:          codec.TypeAsset,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    req.KeyVersion,
	}
	headerBytes := codec.EncodeHeader(header)

	assetPayload := codec.AssetPayload{
		UNSPSC:        req.UNSPSC,
		HasUID:        hasUID,
		AssetUID:      assetUID,
		AssetIDRaw:    raw16,
		UnencryptedID: unencID,
	}

	payloadBytes, err := codec.EncodeAssetPayload(assetPayload)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid asset payload: "+err.Error())
		return
	}

	message := append(headerBytes[:], payloadBytes...)

	resp, err := h.signAndBuildResponse(r.Context(), req.TenantID, req.KeyVersion, "asset", message)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp.UnencryptedID = unencID

	writeJSON(w, http.StatusOK, resp)
}

// MintUser handles Type 3 User VID QR generation (14-digit numeric).
func (h *Handler) MintUser(w http.ResponseWriter, r *http.Request) {
	var req MintUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}

	if req.TenantID == "" {
		writeJSONError(w, http.StatusBadRequest, "tenant_id is required for User QRs")
		return
	}
	if req.KeyVersion == 0 {
		req.KeyVersion = 1
	}

	header := codec.Header{
		Type:          codec.TypeUser,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    req.KeyVersion,
	}
	headerBytes := codec.EncodeHeader(header)

	userPayload := codec.UserPayload{
		VID: req.VID,
	}

	payloadBytes, err := codec.EncodeUserPayload(userPayload)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid VID: "+err.Error())
		return
	}

	// Message to sign = Header (2B) + Payload (6B) = 8B
	message := append(headerBytes[:], payloadBytes[:]...)

	resp, err := h.signAndBuildResponse(r.Context(), req.TenantID, req.KeyVersion, "user", message)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp.UnencryptedID = req.VID

	writeJSON(w, http.StatusOK, resp)
}

// MintOther handles Type 4 Extensible/IoT QR generation.
func (h *Handler) MintOther(w http.ResponseWriter, r *http.Request) {
	var req MintOtherRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}

	if req.TenantID == "" {
		writeJSONError(w, http.StatusBadRequest, "tenant_id is required for Other QRs")
		return
	}
	if req.KeyVersion == 0 {
		req.KeyVersion = 1
	}

	header := codec.Header{
		Type:          codec.TypeOther,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    req.KeyVersion,
	}
	headerBytes := codec.EncodeHeader(header)

	var metaBytes []byte
	if strings.HasPrefix(req.Metadata, "0x") || strings.HasPrefix(req.Metadata, "0X") {
		metaBytes, _ = hex.DecodeString(req.Metadata[2:])
	} else {
		metaBytes = []byte(req.Metadata)
	}

	otherPayload := codec.OtherPayload{
		Subtype:  req.Subtype,
		EntityID: req.EntityID,
		Metadata: metaBytes,
	}

	payloadBytes, err := codec.EncodeOtherPayload(otherPayload)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	message := append(headerBytes[:], payloadBytes...)

	resp, err := h.signAndBuildResponse(r.Context(), req.TenantID, req.KeyVersion, "other", message)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp.UnencryptedID = req.EntityID

	writeJSON(w, http.StatusOK, resp)
}

// MintBatchLocation handles bulk Location QR generation in a single request.
func (h *Handler) MintBatchLocation(w http.ResponseWriter, r *http.Request) {
	var req MintBatchLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}
	if req.TenantID == "" {
		req.TenantID = "00000000000000"
	}
	if req.KeyVersion == 0 {
		req.KeyVersion = 1
	}
	if len(req.Items) == 0 {
		writeJSONError(w, http.StatusBadRequest, "items array must not be empty")
		return
	}

	resp := BatchMintResponse{TenantID: req.TenantID, Type: "location", KeyVersion: req.KeyVersion, TotalCount: len(req.Items)}
	resp.Results = make([]BatchMintResult, len(req.Items))

	for i, item := range req.Items {
		cc := item.CountryCode
		if cc == 0 {
			cc = req.CountryCode
		}
		rawUIDStr := toString(item.LocationUID)
		raw16, locUID, unencID, is16, err := codec.ParseLocationUIDString(rawUIDStr)
		if err != nil {
			resp.Results[i] = BatchMintResult{Index: i, Error: "failed to parse location_uid: " + err.Error()}
			resp.ErrorCount++
			continue
		}

		header := codec.Header{Type: codec.TypeLocation, FormatVersion: codec.FormatVersion1, KeyVersion: req.KeyVersion}
		headerBytes := codec.EncodeHeader(header)
		payload := codec.LocationPayload{
			CountryCode:   cc,
			Subtype:       codec.ParseLocationSubtype(item.Subtype),
			HasUID:        true,
			LocationUID:   locUID,
			LocationIDRaw: raw16,
			UnencryptedID: unencID,
		}
		if !is16 && locUID == 0 && strings.TrimSpace(rawUIDStr) == "" {
			payload.HasUID = false
		}
		payloadBytes := codec.EncodeLocationPayload(payload)
		message := append(headerBytes[:], payloadBytes...)
		out, err := h.signAndBuildResponse(r.Context(), req.TenantID, req.KeyVersion, "location", message)
		if err != nil {
			resp.Results[i] = BatchMintResult{Index: i, Error: err.Error()}
			resp.ErrorCount++
			continue
		}
		resp.Results[i] = BatchMintResult{
			Index:           i,
			UnencryptedID:   unencID,
			TokenBase64URL:  out.TokenBase64URL,
			TokenBase45:     out.TokenBase45,
			FullURL:         out.FullURL,
			QRFormula:       out.QRFormula,
			QRFormulaBase45: out.QRFormulaVersion4,
		}
		resp.SuccessCount++
	}
	writeJSON(w, http.StatusOK, resp)
}

// MintBatchAsset handles bulk Asset QR generation in a single request.
func (h *Handler) MintBatchAsset(w http.ResponseWriter, r *http.Request) {
	var req MintBatchAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}
	if req.TenantID == "" {
		writeJSONError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if req.KeyVersion == 0 {
		req.KeyVersion = 1
	}
	if len(req.Items) == 0 {
		writeJSONError(w, http.StatusBadRequest, "items array must not be empty")
		return
	}

	resp := BatchMintResponse{TenantID: req.TenantID, Type: "asset", KeyVersion: req.KeyVersion, TotalCount: len(req.Items)}
	resp.Results = make([]BatchMintResult, len(req.Items))

	for i, item := range req.Items {
		rawUIDStr := toString(item.AssetUID)
		raw16, assetUID, unencID, is16, err := codec.ParseAssetUIDString(rawUIDStr)
		if err != nil {
			resp.Results[i] = BatchMintResult{Index: i, Error: "failed to parse asset_uid: " + err.Error()}
			resp.ErrorCount++
			continue
		}

		header := codec.Header{Type: codec.TypeAsset, FormatVersion: codec.FormatVersion1, KeyVersion: req.KeyVersion}
		headerBytes := codec.EncodeHeader(header)
		assetPayload := codec.AssetPayload{
			UNSPSC:        item.UNSPSC,
			HasUID:        true,
			AssetUID:      assetUID,
			AssetIDRaw:    raw16,
			UnencryptedID: unencID,
		}
		if !is16 && assetUID == 0 && strings.TrimSpace(rawUIDStr) == "" {
			assetPayload.HasUID = false
		}
		payloadBytes, err := codec.EncodeAssetPayload(assetPayload)
		if err != nil {
			resp.Results[i] = BatchMintResult{Index: i, Error: "invalid asset payload: " + err.Error()}
			resp.ErrorCount++
			continue
		}
		message := append(headerBytes[:], payloadBytes...)
		out, err := h.signAndBuildResponse(r.Context(), req.TenantID, req.KeyVersion, "asset", message)
		if err != nil {
			resp.Results[i] = BatchMintResult{Index: i, Error: err.Error()}
			resp.ErrorCount++
			continue
		}
		resp.Results[i] = BatchMintResult{
			Index:           i,
			UnencryptedID:   unencID,
			TokenBase64URL:  out.TokenBase64URL,
			TokenBase45:     out.TokenBase45,
			FullURL:         out.FullURL,
			QRFormula:       out.QRFormula,
			QRFormulaBase45: out.QRFormulaVersion4,
		}
		resp.SuccessCount++
	}
	writeJSON(w, http.StatusOK, resp)
}

// MintBatchUser handles bulk User VID QR generation from a list of VIDs in a single request.
func (h *Handler) MintBatchUser(w http.ResponseWriter, r *http.Request) {
	var req MintBatchUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}
	if req.TenantID == "" {
		writeJSONError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if req.KeyVersion == 0 {
		req.KeyVersion = 1
	}
	if len(req.VIDs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "vids array must not be empty")
		return
	}

	resp := BatchMintResponse{TenantID: req.TenantID, Type: "user", KeyVersion: req.KeyVersion, TotalCount: len(req.VIDs)}
	resp.Results = make([]BatchMintResult, len(req.VIDs))

	for i, vid := range req.VIDs {
		header := codec.Header{Type: codec.TypeUser, FormatVersion: codec.FormatVersion1, KeyVersion: req.KeyVersion}
		headerBytes := codec.EncodeHeader(header)
		payloadBytes, err := codec.EncodeUserPayload(codec.UserPayload{VID: vid})
		if err != nil {
			resp.Results[i] = BatchMintResult{Index: i, Error: "invalid VID '" + vid + "': " + err.Error()}
			resp.ErrorCount++
			continue
		}
		message := append(headerBytes[:], payloadBytes[:]...)
		out, err := h.signAndBuildResponse(r.Context(), req.TenantID, req.KeyVersion, "user", message)
		if err != nil {
			resp.Results[i] = BatchMintResult{Index: i, Error: err.Error()}
			resp.ErrorCount++
			continue
		}
		resp.Results[i] = BatchMintResult{
			Index:           i,
			UnencryptedID:   vid,
			TokenBase64URL:  out.TokenBase64URL,
			TokenBase45:     out.TokenBase45,
			FullURL:         out.FullURL,
			QRFormula:       out.QRFormula,
			QRFormulaBase45: out.QRFormulaVersion4,
		}
		resp.SuccessCount++
	}
	writeJSON(w, http.StatusOK, resp)
}

// MintBatchOther handles bulk IoT/Other QR generation in a single request.
func (h *Handler) MintBatchOther(w http.ResponseWriter, r *http.Request) {
	var req MintBatchOtherRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}
	if req.TenantID == "" {
		writeJSONError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if req.KeyVersion == 0 {
		req.KeyVersion = 1
	}
	if len(req.Items) == 0 {
		writeJSONError(w, http.StatusBadRequest, "items array must not be empty")
		return
	}

	resp := BatchMintResponse{TenantID: req.TenantID, Type: "other", KeyVersion: req.KeyVersion, TotalCount: len(req.Items)}
	resp.Results = make([]BatchMintResult, len(req.Items))

	for i, item := range req.Items {
		header := codec.Header{Type: codec.TypeOther, FormatVersion: codec.FormatVersion1, KeyVersion: req.KeyVersion}
		headerBytes := codec.EncodeHeader(header)
		var metaBytes []byte
		if strings.HasPrefix(item.Metadata, "0x") || strings.HasPrefix(item.Metadata, "0X") {
			metaBytes, _ = hex.DecodeString(item.Metadata[2:])
		} else {
			metaBytes = []byte(item.Metadata)
		}
		payloadBytes, err := codec.EncodeOtherPayload(codec.OtherPayload{Subtype: item.Subtype, EntityID: item.EntityID, Metadata: metaBytes})
		if err != nil {
			resp.Results[i] = BatchMintResult{Index: i, Error: err.Error()}
			resp.ErrorCount++
			continue
		}
		message := append(headerBytes[:], payloadBytes...)
		out, err := h.signAndBuildResponse(r.Context(), req.TenantID, req.KeyVersion, "other", message)
		if err != nil {
			resp.Results[i] = BatchMintResult{Index: i, Error: err.Error()}
			resp.ErrorCount++
			continue
		}
		resp.Results[i] = BatchMintResult{
			Index:           i,
			UnencryptedID:   item.EntityID,
			TokenBase64URL:  out.TokenBase64URL,
			TokenBase45:     out.TokenBase45,
			FullURL:         out.FullURL,
			QRFormula:       out.QRFormula,
			QRFormulaBase45: out.QRFormulaVersion4,
		}
		resp.SuccessCount++
	}
	writeJSON(w, http.StatusOK, resp)
}

// DecodeQR decodes, verifies, and unpacks any Scheme 3 QR token.
func (h *Handler) DecodeQR(w http.ResponseWriter, r *http.Request) {
	var req DecodeQRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}

	tokenStr := strings.TrimSpace(req.Token)
	if tokenStr == "" {
		writeJSONError(w, http.StatusBadRequest, "token is required")
		return
	}

	// Extract raw token from URL or raw string
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
			writeJSON(w, http.StatusOK, DecodeQRResponse{
				IsValid: false,
				Error:   "invalid token encoding (expected Base64URL or RFC 9285 Base45): " + err.Error(),
			})
			return
		}
	}

	if len(rawBytes) < codec.HeaderLength+codec.SignatureLength {
		writeJSON(w, http.StatusOK, DecodeQRResponse{
			IsValid: false,
			Error:   fmt.Sprintf("token too short: %d bytes (minimum %d bytes)", len(rawBytes), codec.HeaderLength+codec.SignatureLength),
		})
		return
	}

	headerBytes := rawBytes[:codec.HeaderLength]
	header, err := codec.DecodeHeader(headerBytes)
	if err != nil {
		writeJSON(w, http.StatusOK, DecodeQRResponse{
			IsValid: false,
			Error:   "invalid token header: " + err.Error(),
		})
		return
	}

	sigBytes := rawBytes[len(rawBytes)-codec.SignatureLength:]
	messageBytes := rawBytes[:len(rawBytes)-codec.SignatureLength]
	payloadBytes := messageBytes[codec.HeaderLength:]

	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = "62000000000000" // default cluster
	}

	// Verify cryptographic signature
	rec, err := h.keystore.GetTenantKey(r.Context(), tenantID, header.KeyVersion)
	isValid := false
	if err == nil {
		isValid = crypto.Verify(rec.PublicKey, messageBytes, sigBytes)
	}

	resp := DecodeQRResponse{
		IsValid:       isValid,
		Scheme:        3,
		Type:          header.Type.String(),
		KeyVersion:    header.KeyVersion,
		TenantID:      tenantID,
		RawBytesCount: len(rawBytes),
		SignatureHex:  hex.EncodeToString(sigBytes),
	}

	switch header.Type {
	case codec.TypeLocation:
		locPayload, decErr := codec.DecodeLocationPayload(payloadBytes)
		if decErr == nil {
			resp.CountryCode = locPayload.CountryCode
			resp.Subtype = locPayload.Subtype.String()
			resp.LocationUID = locPayload.LocationUID
			resp.UnencryptedID = locPayload.UnencryptedID
			resp.LocationID = locPayload.UnencryptedID
			if locPayload.UnencryptedID != "" {
				isReg, _ := h.dedupEngine.IsLocationIDRegistered(r.Context(), tenantID, locPayload.UnencryptedID)
				resp.IsRegistered = isReg
			}
		}
	case codec.TypeAsset:
		assetPayload, decErr := codec.DecodeAssetPayload(payloadBytes)
		if decErr == nil {
			resp.UNSPSC = assetPayload.UNSPSC
			resp.UNSPSCTitle = codec.GetUNSPSCTitle(assetPayload.UNSPSC)
			resp.AssetUID = assetPayload.AssetUID
			resp.UnencryptedID = assetPayload.UnencryptedID
			resp.AssetID = assetPayload.UnencryptedID
			if assetPayload.UnencryptedID != "" {
				isReg, _ := h.dedupEngine.IsAssetIDRegistered(r.Context(), tenantID, assetPayload.UnencryptedID)
				resp.IsRegistered = isReg
			}
		}
	case codec.TypeUser:
		userPayload, decErr := codec.DecodeUserPayload(payloadBytes)
		if decErr == nil {
			resp.VID = userPayload.VID
			resp.UnencryptedID = userPayload.VID
		}
	case codec.TypeOther:
		otherPayload, decErr := codec.DecodeOtherPayload(payloadBytes)
		if decErr == nil {
			resp.OtherSubtype = otherPayload.Subtype
			resp.EntityID = otherPayload.EntityID
			resp.MetadataHex = hex.EncodeToString(otherPayload.Metadata)
			resp.UnencryptedID = otherPayload.EntityID
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// GenerateTenantKey provisions a new Ed25519 key pair for a 14-digit tenant.
func (h *Handler) GenerateTenantKey(w http.ResponseWriter, r *http.Request) {
	var req GenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}

	if req.TenantID == "" {
		writeJSONError(w, http.StatusBadRequest, "tenant_id (14-digit numeric) is required")
		return
	}
	if req.KeyVersion == 0 {
		req.KeyVersion = 1
	}

	rec, err := h.keystore.GenerateTenantKey(r.Context(), req.TenantID, req.KeyVersion)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate tenant key: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, GenerateKeyResponse{
		TenantID:     rec.TenantID,
		KeyVersion:   rec.KeyVersion,
		PublicKeyHex: hex.EncodeToString(rec.PublicKey),
		PublicKeyB64: crypto.EncodeBase64URL(rec.PublicKey),
		CreatedAt:    rec.CreatedAt.Format(time.RFC3339),
	})
}

// GetPublicKey retrieves the public key for mobile app distribution.
func (h *Handler) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = "00000000000000" // Global
	}

	keyVerStr := r.URL.Query().Get("key_version")
	keyVer := uint8(1)
	if keyVerStr != "" {
		if kv, err := strconv.ParseUint(keyVerStr, 10, 8); err == nil {
			keyVer = uint8(kv)
		}
	}

	rec, err := h.keystore.GetTenantKey(r.Context(), tenantID, keyVer)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "tenant public key not found: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, GenerateKeyResponse{
		TenantID:     rec.TenantID,
		KeyVersion:   rec.KeyVersion,
		PublicKeyHex: hex.EncodeToString(rec.PublicKey),
		PublicKeyB64: crypto.EncodeBase64URL(rec.PublicKey),
		CreatedAt:    rec.CreatedAt.Format(time.RFC3339),
	})
}

// Helper: Signs message with Tenant Private Key and formats response.
// Auto-provisions a new key for the tenant if none exists yet (Just-In-Time key generation).
func (h *Handler) signAndBuildResponse(ctx context.Context, tenantID string, keyVer uint8, typeName string, message []byte) (*MintResponse, error) {
	privKey, err := h.keystore.GetDecryptedPrivateKey(ctx, tenantID, keyVer)
	if err != nil {
		// Auto-provision: if key not found, generate and persist it now
		if _, genErr := h.keystore.GenerateTenantKey(ctx, tenantID, keyVer); genErr != nil {
			return nil, fmt.Errorf("tenant key not found and auto-provisioning failed: %w", genErr)
		}
		// Retry fetching the newly generated key
		privKey, err = h.keystore.GetDecryptedPrivateKey(ctx, tenantID, keyVer)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve auto-provisioned key: %w", err)
		}
	}

	sig, err := crypto.Sign(privKey, message)
	if err != nil {
		return nil, err
	}

	// Full Token = Message + Signature (64B)
	fullToken := append(message, sig...)
	tokenB64 := crypto.EncodeBase64URL(fullToken)
	tokenWithScheme := sheets.SchemePrefix + tokenB64
	fullURL := sheets.BuildFullURL(tokenB64)
	tokenB45 := sheets.SchemePrefix + crypto.EncodeBase45(fullToken)

	return &MintResponse{
		TenantID:          tenantID,
		Type:              typeName,
		KeyVersion:        keyVer,
		RawBytesCount:     len(fullToken),
		TokenBase64URL:    tokenWithScheme,
		TokenBase45:       tokenB45,
		FullURL:           fullURL,
		QRFormula:         sheets.BuildGoogleSheetsFormula(fullURL),
		QRFormulaVersion4: fmt.Sprintf(`=IMAGE("https://api.qrserver.com/v1/create-qr-code/?size=310x310&ecc=L&margin=1&data=" & ENCODEURL("%s"))`, tokenB45),
		QRFormulaCellA2:   sheets.BuildGoogleSheetsCellFormula("A2"),
	}, nil
}

func toString(val any) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatUint(uint64(v), 10)
	case int:
		return strconv.Itoa(v)
	case uint64:
		return strconv.FormatUint(v, 10)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func writeJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}
