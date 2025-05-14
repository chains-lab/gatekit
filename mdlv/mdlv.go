package mdlv

import (
	"context"
	"net/http"
	"strings"

	"github.com/chains-lab/gatekit/httpkit"
	"github.com/chains-lab/gatekit/roles"
	"github.com/chains-lab/gatekit/tokens"
	"github.com/google/uuid"
)

func AuthMdl(skAccount, skService string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusUnauthorized,
					Title:  "Unauthorized",
					Detail: "Missing Authorization header",
				})...)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusUnauthorized,
					Title:  "Unauthorized",
					Detail: "Invalid Authorization header",
				})...)
				return
			}

			tokenString := parts[1]

			serviceData, err := tokens.VerifyServiceJWT(ctx, tokenString, skService)
			if err == nil {
				ctx = context.WithValue(ctx, tokens.ServerKey, serviceData.Subject)
				ctx = context.WithValue(ctx, tokens.AudienceKey, serviceData.Audience)

				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			userData, err := tokens.VerifyAccountsJWT(r.Context(), tokenString, skAccount)
			if err != nil {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusUnauthorized,
					Title:  "Unauthorized",
					Detail: "Token validation failed",
				})...)
				return
			}

			ctx = context.WithValue(ctx, tokens.SubjectIDKey, userData.Subject)
			ctx = context.WithValue(ctx, tokens.SessionIDKey, userData.Session)
			ctx = context.WithValue(ctx, tokens.SubscriptionKey, userData.Subscription)
			ctx = context.WithValue(ctx, tokens.RoleKey, userData.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AccessGrant(skAccount, skService string, roles ...roles.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusUnauthorized,
					Title:  "Unauthorized",
					Detail: "Missing Authorization header",
				})...)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusUnauthorized,
					Title:  "Unauthorized",
					Detail: "Invalid Authorization header",
				})...)
				return
			}

			tokenString := parts[1]

			serviceData, err := tokens.VerifyServiceJWT(ctx, tokenString, skService)
			if err == nil {
				ctx = context.WithValue(ctx, tokens.ServerKey, serviceData.Subject)
				ctx = context.WithValue(ctx, tokens.AudienceKey, serviceData.Audience)

				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			userData, err := tokens.VerifyAccountsJWT(ctx, tokenString, skAccount)
			if err != nil {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusUnauthorized,
					Title:  "Unauthorized",
					Detail: "Token validation failed",
				})...)
				return
			}

			roleAllowed := false
			for _, role := range roles {
				if userData.Role == role {
					roleAllowed = true
					break
				}
			}
			if !roleAllowed {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusForbidden,
					Title:  "Forbidden",
					Detail: "User role not allowed",
				})...)
				return
			}

			ctx = context.WithValue(ctx, tokens.SubjectIDKey, userData.Subject)
			ctx = context.WithValue(ctx, tokens.SessionIDKey, userData.Session)
			ctx = context.WithValue(ctx, tokens.SubscriptionKey, userData.Subscription)
			ctx = context.WithValue(ctx, tokens.RoleKey, userData.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func SubMdl(sk string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusUnauthorized,
					Title:  "Unauthorized",
					Detail: "Missing Authorization header",
				})...)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusUnauthorized,
					Title:  "Unauthorized",
					Detail: "Invalid Authorization header",
				})...)
				return
			}

			tokenString := parts[1]

			serviceData, err := tokens.VerifyServiceJWT(ctx, tokenString, sk)
			if err == nil {
				ctx = context.WithValue(ctx, tokens.ServerKey, serviceData.Subject)
				ctx = context.WithValue(ctx, tokens.AudienceKey, serviceData.Audience)

				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			tokenData, err := tokens.VerifyAccountsJWT(ctx, tokenString, sk)
			if err != nil {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusUnauthorized,
					Title:  "Unauthorized",
					Detail: "Token validation failed",
				})...)
				return
			}

			if tokenData.Subscription == uuid.Nil {
				httpkit.RenderErr(w, httpkit.ResponseError(httpkit.ResponseErrorInput{
					Status: http.StatusForbidden,
					Title:  "Forbidden",
					Detail: "Not allowed for user subscription",
				})...)
				return
			}

			ctx = context.WithValue(ctx, tokens.SubjectIDKey, tokenData.Subject)
			ctx = context.WithValue(ctx, tokens.SessionIDKey, tokenData.Session)
			ctx = context.WithValue(ctx, tokens.SubscriptionKey, tokenData.Subscription)
			ctx = context.WithValue(ctx, tokens.RoleKey, tokenData.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
