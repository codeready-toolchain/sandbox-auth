package goamiddleware

import (
	"github.com/codeready-toolchain/sandbox-auth/pkg/authorization/token/manager"
	"net/http"
)

func TokenManagerContext(tm manager.TokenManager) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = manager.ContextWithTokenManager(ctx, tm)
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
