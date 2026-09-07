package http

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

// HTTPAuthMiddleware требует заголовок "authorization: Bearer <secret>".
func HTTPAuthMiddleware(secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			respondWithError(w, http.StatusUnauthorized, "authorization header format must be 'Bearer <secret>'")
			return
		}

		if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(secret)) != 1 {
			respondWithError(w, http.StatusUnauthorized, "invalid secret")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"error":%q}`, message)))
}
