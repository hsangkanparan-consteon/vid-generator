package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
)

// RunStdioServer listens on Stdin and writes JSON-RPC 2.0 responses to Stdout until EOF.
func (s *Server) RunStdioServer(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// Support up to 10MB JSON payloads
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	encoder := json.NewEncoder(out)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Error: &JSONRPCError{
					Code:    ErrCodeParseError,
					Message: "failed to parse JSON-RPC: " + err.Error(),
				},
			}
			_ = encoder.Encode(resp)
			continue
		}

		resp := s.HandleRPC(ctx, req)
		if resp.ID != nil || resp.Error != nil {
			if err := encoder.Encode(resp); err != nil {
				return err
			}
		}
	}

	return scanner.Err()
}

// ServeStdio is a convenient entrypoint for Stdin/Stdout execution.
func (s *Server) ServeStdio() error {
	return s.RunStdioServer(context.Background(), os.Stdin, os.Stdout)
}
