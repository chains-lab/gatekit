package mdlv

import (
	"net/http"

	"github.com/chains-lab/ape"
	"github.com/chains-lab/ape/problems"
	"github.com/chains-lab/gatekit/auth"
	"github.com/chains-lab/gatekit/roles"
)

func AccessGrant(ctxKey interface{}, allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			user, ok := ctx.Value(ctxKey).(auth.UserData)
			if !ok {
				ape.RenderErr(w,
					problems.Unauthorized("Missing AuthorizationHeader header"),
				)

				return
			}

			if err := roles.ParseRole(user.Role); err != nil {
				ape.RenderErr(w,
					problems.Unauthorized("User role not valid"),
				)

				return
			}

			roleAllowed := false
			for _, role := range allowedRoles {
				if user.Role == role {
					roleAllowed = true
					break
				}
			}
			if !roleAllowed {
				ape.RenderErr(w,
					problems.Forbidden("User role not allowed"),
				)

				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
