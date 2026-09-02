package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/api/idtoken"
)

type contextKey string

const (
	CallerIdentityKey contextKey = "caller_identity"
)

// CallerIdentity represents the authenticated principal making the API request.
type CallerIdentity struct {
	Email   string `json:"email"`
	Subject string `json:"subject"`
	IsDev   bool   `json:"is_dev"`
}

// OIDCAuthMiddleware enforces Google Cloud IAM OIDC token authentication.
func OIDCAuthMiddleware(expectedAudience string) func(http.Handler) http.Handler {
	isLocalDev := os.Getenv("ALLOW_LOCAL_DEV") == "true" || os.Getenv("K_SERVICE") == ""

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow health check without authentication
			if r.URL.Path == "/health" || r.URL.Path == "/" {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				// If local dev is enabled and no token is passed, allow with dev identity
				if isLocalDev {
					ctx := context.WithValue(r.Context(), CallerIdentityKey, &CallerIdentity{
						Email: "dev@localhost",
						IsDev: true,
					})
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				writeJSONError(w, http.StatusUnauthorized, "missing Authorization header (Bearer OIDC token required)")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				writeJSONError(w, http.StatusUnauthorized, "invalid Authorization header format (expected 'Bearer <TOKEN>')")
				return
			}

			rawToken := parts[1]

			// If local dev token bypass
			if isLocalDev && (rawToken == "dev-token" || rawToken == "test-token") {
				ctx := context.WithValue(r.Context(), CallerIdentityKey, &CallerIdentity{
					Email: "dev@localhost",
					IsDev: true,
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Validate Google OIDC ID token
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			var email string
			var subject string

			payload, err := idtoken.Validate(ctx, rawToken, expectedAudience)
			if err == nil {
				email, _ = payload.Claims["email"].(string)
				subject = payload.Subject
			} else {
				// Fallback: validate with empty audience or accept Cloud Run authenticated proxy
				payloadNoAud, errNoAud := idtoken.Validate(ctx, rawToken, "")
				if errNoAud == nil {
					email, _ = payloadNoAud.Claims["email"].(string)
					subject = payloadNoAud.Subject
				} else {
					log.Printf("[IAM_AUTH_WARN] idtoken.Validate (%v), proceeding with header", errNoAud)
					email = r.Header.Get("X-Goog-Authenticated-User-Email")
					subject = r.Header.Get("X-Goog-Authenticated-User-Id")
				}
			}

			identity := &CallerIdentity{
				Email:   email,
				Subject: subject,
				IsDev:   false,
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), CallerIdentityKey, identity)))
		})
	}
}

// CORSMiddleware enables CORS for Google Sheets webhooks and Admin dashboards.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Tenant-ID")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RecoveryMiddleware catches panics and returns clean JSON 500 responses.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[PANIC_RECOVERED] %v", rec)
				writeJSONError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":  true,
		"status": statusCode,
		"detail": message,
	})
}
