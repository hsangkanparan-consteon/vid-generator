package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"consteon.com/qr-generator/internal/codec"
	"consteon.com/qr-generator/internal/crypto"
	"consteon.com/qr-generator/internal/keystore"
	"consteon.com/qr-generator/internal/kms"
	"consteon.com/qr-generator/internal/mcp"
	"consteon.com/qr-generator/pkg/sheets"
	"consteon.com/qr-generator/pkg/verifier"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "mcp":
		handleMCPStdio()
	case "gen-key":
		handleGenKey(os.Args[2:])
	case "mint-loc":
		handleMintLocation(os.Args[2:])
	case "mint-asset":
		handleMintAsset(os.Args[2:])
	case "mint-user":
		handleMintUser(os.Args[2:])
	case "verify":
		handleVerify(os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Consteon QR Generator & Offline Verifier CLI (Version 6 Target)

Usage:
  qr-cli <command> [flags]

Commands:
  mcp          Run as Model Context Protocol (MCP) Stdio server for AI agents (Cursor/Claude)
  gen-key      Generate a new Ed25519 key pair for a 14-digit tenant
  mint-loc     Mint a Location QR code (69B generic or 74B specific with UID)
  mint-asset   Mint an Asset QR code with 4/6-digit UNSPSC (69B generic or 74B specific with UID)
  mint-user    Mint a User QR code with 14-digit numeric VID (72 bytes)
  verify       Verify an autsorz QR URL offline using a public key

Key Formats Supported:
  Both Hex and Base64 / Base64URL formats are automatically detected.

UID Formats Supported:
  - Numeric integer (e.g. -uid 123456)
  - Alphanumeric string (e.g. -uid "CAR-2026-XYZ-998812") -> deterministic SHA256 5-byte hash
  - Omitted (e.g. no -uid flag) -> generic category QR without UID (69 bytes total)

Examples:
  qr-cli gen-key -tenant 10002000300040
  qr-cli mint-loc -tenant 10002000300040 -country 360 -subtype gate -privkey <KEY>
  qr-cli mint-asset -tenant 10002000300040 -unspsc 251015 -privkey <KEY>
  qr-cli mint-asset -tenant 10002000300040 -unspsc 251015 -uid "CAR-99" -privkey <KEY>
  qr-cli mint-user -tenant 10002000300040 -vid 12345678901234 -privkey <KEY>
  qr-cli verify -url "https://autsorz/l/3AQEB..." -pubkey <HEX_OR_BASE64>`)
}

func parsePrivateKey(s string) (ed25519.PrivateKey, error) {
	clean := strings.TrimSpace(s)
	if clean == "" {
		return nil, errors.New("empty private key string")
	}

	// 1. Try Hex
	if b, err := hex.DecodeString(clean); err == nil && len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}

	// 2. Try Base64URL
	if b, err := crypto.DecodeBase64URL(clean); err == nil && len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}

	// 3. Try standard Base64
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil && len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}

	return nil, fmt.Errorf("invalid private key: expected 64 bytes (128 hex chars or ~86 base64 chars)")
}

func parsePublicKey(s string) (ed25519.PublicKey, error) {
	clean := strings.TrimSpace(s)
	if clean == "" {
		return nil, errors.New("empty public key string")
	}

	// 1. Try Hex
	if b, err := hex.DecodeString(clean); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}

	// 2. Try Base64URL
	if b, err := crypto.DecodeBase64URL(clean); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}

	// 3. Try standard Base64
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}

	return nil, fmt.Errorf("invalid public key: expected 32 bytes (64 hex chars or 43 base64 chars)")
}

func handleMCPStdio() {
	ctx := context.Background()
	mockKMS, _ := kms.NewMockKMSClient()
	store := keystore.NewEncryptedKeystore(mockKMS)
	_, _ = store.GenerateTenantKey(ctx, "00000000000000", 1)

	server := mcp.NewServer(store)
	if err := server.ServeStdio(); err != nil {
		os.Exit(1)
	}
}

func handleGenKey(args []string) {
	fs := flag.NewFlagSet("gen-key", flag.ExitOnError)
	tenantID := fs.String("tenant", "00000000000000", "14-digit numeric tenant ID")
	keyVer := fs.Int("version", 1, "Key version number")
	_ = fs.Parse(args)

	ctx := context.Background()
	mockKMS, _ := kms.NewMockKMSClient()
	store := keystore.NewEncryptedKeystore(mockKMS)

	rec, err := store.GenerateTenantKey(ctx, *tenantID, uint8(*keyVer))
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		os.Exit(1)
	}

	privKey, _ := store.GetDecryptedPrivateKey(ctx, *tenantID, uint8(*keyVer))

	fmt.Println("--- NEW TENANT KEY GENERATED ---")
	fmt.Printf("Tenant ID:        %s\n", rec.TenantID)
	fmt.Printf("Key Version:      %d\n", rec.KeyVersion)
	fmt.Printf("Public Key (Hex): %x\n", rec.PublicKey)
	fmt.Printf("Public Key (B64): %s\n", crypto.EncodeBase64URL(rec.PublicKey))
	fmt.Printf("Private Key(Hex): %x\n", privKey)
	fmt.Printf("Private Key(B64): %s\n", crypto.EncodeBase64URL(privKey))
}

func handleMintLocation(args []string) {
	fs := flag.NewFlagSet("mint-loc", flag.ExitOnError)
	tenantID := fs.String("tenant", "00000000000000", "14-digit numeric tenant ID")
	country := fs.Int("country", 360, "ISO 3166-1 country code")
	subtype := fs.String("subtype", "gate", "Location subtype (portal, guard_station, room, toilet, gate, checkpoint)")
	uid := fs.String("uid", "", "Location UID (numeric, string name, or omitted for generic location)")
	privInput := fs.String("privkey", "", "64-byte private key in Hex or Base64 format")
	_ = fs.Parse(args)

	var privKey ed25519.PrivateKey
	var pubKey ed25519.PublicKey

	if *privInput != "" {
		var err error
		privKey, err = parsePrivateKey(*privInput)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		pubKey = privKey.Public().(ed25519.PublicKey)
	} else {
		pubKey, privKey, _ = crypto.GenerateKeyPair()
	}

	hasUID := false
	var locationUID uint64
	if strings.TrimSpace(*uid) != "" {
		var err error
		locationUID, err = codec.ResolveUID40(*uid)
		if err != nil {
			fmt.Printf("Error resolving Location UID: %v\n", err)
			os.Exit(1)
		}
		hasUID = true
	}

	header := codec.EncodeHeader(codec.Header{
		Type:          codec.TypeLocation,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    1,
	})

	payload := codec.EncodeLocationPayload(codec.LocationPayload{
		CountryCode: uint16(*country),
		Subtype:     codec.ParseLocationSubtype(*subtype),
		HasUID:      hasUID,
		LocationUID: locationUID,
	})

	message := append(header[:], payload...)
	sig, _ := crypto.Sign(privKey, message)
	fullToken := append(message, sig...)

	tokenB64 := crypto.EncodeBase64URL(fullToken)
	fullURL := sheets.BuildFullURL(tokenB64)

	printMintResult("Location", *tenantID, fullToken, fullURL, pubKey)
}

func handleMintAsset(args []string) {
	fs := flag.NewFlagSet("mint-asset", flag.ExitOnError)
	tenantID := fs.String("tenant", "10002000300040", "14-digit numeric tenant ID")
	unspsc := fs.String("unspsc", "251015", "UNSPSC classification code (e.g. 251015 for passenger cars, 432115 for computers)")
	uid := fs.String("uid", "", "Asset UID or Serial (numeric, string like 'CAR-99', or omitted for generic category QR)")
	privInput := fs.String("privkey", "", "64-byte private key in Hex or Base64 format")
	_ = fs.Parse(args)

	var privKey ed25519.PrivateKey
	var pubKey ed25519.PublicKey

	if *privInput != "" {
		var err error
		privKey, err = parsePrivateKey(*privInput)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		pubKey = privKey.Public().(ed25519.PublicKey)
	} else {
		pubKey, privKey, _ = crypto.GenerateKeyPair()
	}

	hasUID := false
	var assetUID uint64
	if strings.TrimSpace(*uid) != "" {
		var err error
		assetUID, err = codec.ResolveUID40(*uid)
		if err != nil {
			fmt.Printf("Error resolving Asset UID: %v\n", err)
			os.Exit(1)
		}
		hasUID = true
	}

	header := codec.EncodeHeader(codec.Header{
		Type:          codec.TypeAsset,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    1,
	})

	payload, err := codec.EncodeAssetPayload(codec.AssetPayload{
		UNSPSC:   *unspsc,
		HasUID:   hasUID,
		AssetUID: assetUID,
	})
	if err != nil {
		fmt.Printf("Error encoding asset payload: %v\n", err)
		os.Exit(1)
	}

	message := append(header[:], payload...)
	sig, _ := crypto.Sign(privKey, message)
	fullToken := append(message, sig...)

	tokenB64 := crypto.EncodeBase64URL(fullToken)
	fullURL := sheets.BuildFullURL(tokenB64)

	printMintResult("Asset", *tenantID, fullToken, fullURL, pubKey)
}

func handleMintUser(args []string) {
	fs := flag.NewFlagSet("mint-user", flag.ExitOnError)
	tenantID := fs.String("tenant", "10002000300040", "14-digit numeric tenant ID")
	vid := fs.String("vid", "12345678901234", "14-digit numeric VID")
	privInput := fs.String("privkey", "", "64-byte private key in Hex or Base64 format")
	_ = fs.Parse(args)

	var privKey ed25519.PrivateKey
	var pubKey ed25519.PublicKey

	if *privInput != "" {
		var err error
		privKey, err = parsePrivateKey(*privInput)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		pubKey = privKey.Public().(ed25519.PublicKey)
	} else {
		pubKey, privKey, _ = crypto.GenerateKeyPair()
	}

	header := codec.EncodeHeader(codec.Header{
		Type:          codec.TypeUser,
		FormatVersion: codec.FormatVersion1,
		KeyVersion:    1,
	})

	payload, err := codec.EncodeUserPayload(codec.UserPayload{
		VID: *vid,
	})
	if err != nil {
		fmt.Printf("Error encoding user payload: %v\n", err)
		os.Exit(1)
	}

	message := append(header[:], payload[:]...)
	sig, _ := crypto.Sign(privKey, message)
	fullToken := append(message, sig...)

	tokenB64 := crypto.EncodeBase64URL(fullToken)
	fullURL := sheets.BuildFullURL(tokenB64)

	printMintResult("User", *tenantID, fullToken, fullURL, pubKey)
}

func handleVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	rawURL := fs.String("url", "", "Full URL (https://autsorz/l/3...) or Token String (3...)")
	pubInput := fs.String("pubkey", "", "32-byte public key in Hex or Base64 format")
	_ = fs.Parse(args)

	if *rawURL == "" || *pubInput == "" {
		fmt.Println("Error: both -url and -pubkey are required for verification")
		os.Exit(1)
	}

	pubKey, err := parsePublicKey(*pubInput)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	v := verifier.NewOfflineVerifier()
	v.AddTenantKey(1, pubKey)

	res, err := v.VerifyURL(*rawURL)
	if err != nil {
		fmt.Printf("❌ VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ SIGNATURE VERIFIED SUCCESSFULLY!")
	fmt.Printf("Scheme:         %s (Ed25519 Asymmetric)\n", res.Scheme)
	fmt.Printf("Type:           %s (%d)\n", res.TypeName, res.Type)
	fmt.Printf("Format Version: %d\n", res.FormatVersion)
	fmt.Printf("Key Version:    %d\n", res.KeyVersion)

	if res.Location != nil {
		fmt.Printf("Country Code:   %d\n", res.Location.CountryCode)
		fmt.Printf("Subtype:        %s\n", res.Location.Subtype.String())
		fmt.Printf("Has UID:        %v\n", res.Location.HasUID)
		if res.Location.HasUID {
			fmt.Printf("Location UID:   %d\n", res.Location.LocationUID)
		}
	}
	if res.Asset != nil {
		fmt.Printf("UNSPSC:         %s\n", res.Asset.UNSPSC)
		fmt.Printf("Has UID:        %v\n", res.Asset.HasUID)
		if res.Asset.HasUID {
			fmt.Printf("Asset UID:      %d\n", res.Asset.AssetUID)
		}
	}
	if res.User != nil {
		fmt.Printf("User VID:       %s\n", res.User.VID)
	}
}

func printMintResult(typeName, tenantID string, token []byte, fullURL string, pubKey ed25519.PublicKey) {
	tokenB64 := crypto.EncodeBase64URL(token)
	tokenWithScheme := sheets.SchemePrefix + tokenB64

	fmt.Printf("--- MINTED %s QR TOKEN (Version 6 Target) ---\n", typeName)
	fmt.Printf("Tenant ID:         %s\n", tenantID)
	fmt.Printf("Raw Token Bytes:   %d bytes\n", len(token))
	fmt.Printf("Scheme Prefix:     3 (Ed25519 Asymmetric)\n")
	fmt.Printf("Token String (A2): %s\n", tokenWithScheme)
	fmt.Printf("Public Key (Hex):  %x\n", pubKey)
	fmt.Printf("Public Key (B64):  %s\n", crypto.EncodeBase64URL(pubKey))
	fmt.Printf("Full URL:          %s\n", fullURL)
	fmt.Printf("Google Sheets:     %s\n", sheets.BuildGoogleSheetsFormula(fullURL))
	fmt.Printf("Sheets (Cell A2):  =IMAGE(\"https://api.qrserver.com/v1/create-qr-code/?size=310x310&ecc=M&margin=1&data=\" & ENCODEURL(\"https://autsorz/l/\" & A2))\n")
}
