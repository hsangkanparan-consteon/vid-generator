package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"consteon.com/vid-generator/internal/config"
	"consteon.com/vid-generator/internal/db"
	"consteon.com/vid-generator/internal/mcp"
	"consteon.com/vid-generator/internal/middleware"
	"consteon.com/vid-generator/internal/migration"
	"consteon.com/vid-generator/internal/vid"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "generate":
		handleGenerate(os.Args[2:])
	case "validate":
		handleValidate(os.Args[2:])
	case "import":
		handleImport(os.Args[2:])
	case "mcp":
		handleStdioMCP()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`Consteon VID Generator CLI

Usage:
  vid-cli generate -country <code> -count <n>   Generate sample VIDs locally
  vid-cli validate -vid <14-digit-vid>          Validate checksum and extract address
  vid-cli import   -file <path.csv>             Bulk import VIDs from CSV into Firestore
  vid-cli mcp                                   Run MCP server over Stdio`)
}

func handleGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	country := fs.String("country", "62", "Country code (e.g. 62, 1, 91, 0, 424)")
	count := fs.Int("count", 5, "Number of VIDs to generate")
	fs.Parse(args)

	st := vid.NewSeedTable()
	gen := vid.NewGenerator(st)

	res, err := gen.GenerateBatch(*country, *count)
	if err != nil {
		fmt.Printf("Error generating VIDs: %v\n", err)
		return
	}

	fmt.Printf("Generated %d VIDs for Country '%s' (Attempts: %d, Hit Rate: %.1f%%, Time: %dms):\n\n",
		res.Generated, *country, res.TotalAttempts, res.HitRate, res.DurationMs)

	for i, item := range res.VIDs {
		fmt.Printf("%2d. VID: %s | Address: %012d | Cluster: %07d | Pos: %05d\n",
			i+1, item.VID, item.Address.Address, item.Address.Cluster, item.Address.Position)
	}
}

func handleValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	vidStr := fs.String("vid", "", "14-digit VID string")
	fs.Parse(args)

	if *vidStr == "" {
		fmt.Println("Error: -vid argument is required")
		return
	}

	validator := vid.NewValidator()
	res := validator.Validate(*vidStr)

	data, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(data))
}

func handleImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to CSV file containing VIDs")
	fs.Parse(args)

	if *filePath == "" {
		fmt.Println("Error: -file argument is required")
		return
	}

	cfg := config.LoadFromEnv()
	ctx := context.Background()

	dbClient, err := db.NewClient(ctx, cfg.ProjectID, cfg.DatabaseID)
	if err != nil {
		fmt.Printf("Database connection failed: %v\n", err)
		return
	}
	defer dbClient.Close()

	repo := db.NewRepository(dbClient)
	validator := vid.NewValidator()
	importer := migration.NewImporter(validator, repo)

	fmt.Printf("Starting bulk import from '%s' into Firestore db '%s'...\n", *filePath, cfg.DatabaseID)
	summary, err := importer.ImportCSV(ctx, *filePath)
	if err != nil {
		fmt.Printf("Import failed: %v\n", err)
		return
	}

	fmt.Printf("\nImport Finished:\n- Total Rows: %d\n- Imported: %d\n- Duplicates Skipped: %d\n- Invalid: %d\n- Time: %v\n",
		summary.TotalRows, summary.Imported, summary.Duplicates, summary.InvalidVIDs, summary.ExecutionTime)
}

func handleStdioMCP() {
	cfg := config.LoadFromEnv()
	ctx := context.Background()

	dbClient, err := db.NewClient(ctx, cfg.ProjectID, cfg.DatabaseID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Database connection warning: %v\n", err)
	}
	if dbClient != nil {
		defer dbClient.Close()
	}

	repo := db.NewRepository(dbClient)
	seedTable := vid.NewSeedTable()
	generator := vid.NewGenerator(seedTable)
	validator := vid.NewValidator()
	auditLogger := middleware.NewAuditLogger()
	authorizer := middleware.NewAuthorizer()

	mcpServer := mcp.NewServer(generator, validator, repo, auditLogger, authorizer)

	scanner := bufio.NewScanner(os.Stdin)
	actor := middleware.ActorInfo{
		Identity: "stdio-local-user",
		Role:     string(middleware.RoleAdmin),
	}

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		var req mcp.JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}

		switch req.Method {
		case "initialize":
			resp := mcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: mcp.InitializeResult{
					ProtocolVersion: "2024-11-05",
					Capabilities:    mcp.ServerCapabilities{Tools: &mcp.ToolsCapability{ListChanged: true}},
					ServerInfo:      mcp.Implementation{Name: "consteon-vid-generator-stdio", Version: "1.0.0"},
				},
			}
			data, _ := json.Marshal(resp)
			fmt.Println(string(data))

		case "tools/list":
			resp := mcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]interface{}{"tools": mcpServer.GetTools()},
			}
			data, _ := json.Marshal(resp)
			fmt.Println(string(data))

		case "tools/call":
			var callParams mcp.CallToolParams
			json.Unmarshal(req.Params, &callParams)
			res, _ := mcpServer.CallTool(ctx, actor, callParams)
			resp := mcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  res,
			}
			data, _ := json.Marshal(resp)
			fmt.Println(string(data))
		}
	}
}
