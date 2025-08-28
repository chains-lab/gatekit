package mdlv

import (
	"net/http"
	"strings"

	"github.com/chains-lab/ape"
	"github.com/chains-lab/ape/problems"
	"github.com/chains-lab/gatekit/auth"
)

func ServiceAuthMdl(serviceName, skService string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			h := r.Header.Get(hServiceAuthorization)
			if h == "" {
				ape.RenderErr(w, problems.Unauthorized("failed service authorization: missing X-Service-Authorization header"))

				return
			}

			parts := strings.SplitN(h, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				ape.RenderErr(w, problems.Unauthorized("failed service authorization"))

				return
			}

			svcToken := parts[1]

			svcData, err := auth.VerifyServiceJWT(ctx, svcToken, skService)
			if err != nil {
				ape.RenderErr(w, problems.Unauthorized("failed service authorization: token validation failed"))

				return
			}

			access := false
			for _, v := range svcData.Audience {
				if v == serviceName {
					access = true
					break
				}
			}
			if !access {
				ape.RenderErr(w, problems.Forbidden(
					"failed service authorization: access to the service is forbidden",
				))

				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
