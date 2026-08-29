package middleware

import (
	"errors"
	"strings"
)

type Role string

const (
	RoleAdmin     Role = "vid.admin"
	RoleGenerator Role = "vid.generator"
	RoleConsumer  Role = "vid.consumer"
	RoleReader    Role = "vid.reader"
)

var (
	ErrUnauthorized   = errors.New("unauthorized: missing or invalid authentication")
	ErrForbidden      = errors.New("forbidden: caller role does not have permission for this tool")
)

var RoleHierarchy = map[Role]int{
	RoleAdmin:     4,
	RoleGenerator: 3,
	RoleConsumer:  2,
	RoleReader:    1,
}

var ToolMinRole = map[string]Role{
	"generate_stock":     RoleGenerator,
	"allocate_vid":       RoleConsumer,
	"validate_vid":       RoleReader,
	"import_vids":        RoleAdmin,
	"get_stock_level":    RoleReader,
	"revoke_vid":         RoleAdmin,
	"get_vid_by_address": RoleReader,
	"check_address":      RoleReader,
}

type Authorizer struct{}

func NewAuthorizer() *Authorizer {
	return &Authorizer{}
}

func (a *Authorizer) Authorize(callerRole string, toolName string) error {
	minRole, ok := ToolMinRole[toolName]
	if !ok {
		minRole = RoleAdmin
	}

	role := Role(strings.TrimSpace(callerRole))
	if role == "" {
		role = RoleReader
	}

	callerLevel, exists := RoleHierarchy[role]
	if !exists {
		return ErrForbidden
	}

	requiredLevel := RoleHierarchy[minRole]
	if callerLevel < requiredLevel {
		return ErrForbidden
	}

	return nil
}
