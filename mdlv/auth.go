package mdlv

import (
	"context"
	"net/http"
	"strings"

	"github.com/chains-lab/ape"
	"github.com/chains-lab/ape/problems"
	"github.com/chains-lab/gatekit/auth"
	"github.com/google/uuid"
)

const (
	AuthorizationHeader        = "Authorization"
	ServiceAuthorizationHeader = "X-Service-Authorization" // отдельный заголовок для m2
	IpHeader                   = "X-User-IP"
	UserAgentHeader            = "X-User-Agent"
	ClientTxHeader             = "X-Client-Tx"
)

func Auth(ctxKey interface{}, skUser string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			authHeader := r.Header.Get(AuthorizationHeader)
			if authHeader == "" {
				ape.RenderErr(w,
					problems.Unauthorized("Missing AuthorizationHeader header"),
				)

				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				ape.RenderErr(w,
					problems.Unauthorized("Missing AuthorizationHeader header"),
				)

				return
			}

			tokenString := parts[1]

			userData, err := auth.VerifyUserJWT(r.Context(), tokenString, skUser)
			if err != nil {
				ape.RenderErr(w,
					problems.Unauthorized("Token validation failed"),
				)

				return
			}

			userID, err := uuid.Parse(userData.Subject)
			if err != nil {
				ape.RenderErr(w,
					problems.Unauthorized("User ID is nov valid"),
				)

				return
			}

			ctx = context.WithValue(ctx, ctxKey, auth.UserData{
				ID:        userID,
				SessionID: userData.SessionID,
				Role:      userData.Role,
				Verified:  userData.Verified,
			})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func Ip(ctxKey interface{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			ip := r.Header.Get(IpHeader)
			if ip == "" {
				ape.RenderErr(w,
					problems.Unauthorized("Missing X-User-IP header"),
				)

				return
			}

			ctx = context.WithValue(ctx, ctxKey, ip)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserAgent(ctxKey interface{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			ua := r.Header.Get(UserAgentHeader)
			if ua == "" {
				ape.RenderErr(w,
					problems.Unauthorized("Missing X-User-Agent header"),
				)

				return
			}

			ctx = context.WithValue(ctx, ctxKey, ua)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func Client(ctxKey interface{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			client := r.Header.Get(ClientTxHeader)
			if client == "" {
				ape.RenderErr(w,
					problems.Unauthorized("Missing X-Client-Tx header"),
				)

				return
			}

			ctx = context.WithValue(ctx, ctxKey, client)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
