package middleware

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type AuditEvent struct {
	Severity  string      `json:"severity"`
	Timestamp string      `json:"timestamp"`
	TraceID   string      `json:"logging.googleapis.com/trace,omitempty"`
	Payload   AuditDetail `json:"jsonPayload"`
}

type AuditDetail struct {
	EventType       string      `json:"event_type"`
	Action          string      `json:"action"`
	Result          string      `json:"result"`
	Actor           ActorInfo   `json:"actor"`
	Country         string      `json:"country,omitempty"`
	Count           int         `json:"count,omitempty"`
	VID             string      `json:"vid,omitempty"`
	Address         int64       `json:"address,omitempty"`
	ExecutionTimeMs int64       `json:"execution_time_ms"`
	Metadata        interface{} `json:"metadata,omitempty"`
	ErrorMessage    string      `json:"error_message,omitempty"`
}

type ActorInfo struct {
	Identity  string `json:"identity"`
	Role      string `json:"role"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type AuditLogger struct{}

func NewAuditLogger() *AuditLogger {
	return &AuditLogger{}
}

func (l *AuditLogger) Log(detail AuditDetail) {
	severity := "INFO"
	if detail.Result == "ERROR" {
		severity = "ERROR"
	} else if detail.Result == "DENIED" {
		severity = "WARNING"
	}

	event := AuditEvent{
		Severity:  severity,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Payload:   detail,
	}

	data, err := json.Marshal(event)
	if err == nil {
		fmt.Fprintln(os.Stdout, string(data))
	}
}
