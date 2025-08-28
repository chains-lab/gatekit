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
	hAuthorization        = "Authorization"
	hServiceAuthorization = "X-Service-Authorization" // отдельный заголовок для m2m
	bearerPrefix          = "bearer "
)

func AuthMdl(ctxKey interface{}, skUser string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			authHeader := r.Header.Get(hAuthorization)
			if authHeader == "" {
				ape.RenderErr(w,
					problems.Unauthorized("Missing Authorization header"),
				)

				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				ape.RenderErr(w,
					problems.Unauthorized("Missing Authorization header"),
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
				UserID:    userID,
				SessionID: userData.Session,
				Role:      userData.Role,
				Verified:  userData.Verified,
			})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
