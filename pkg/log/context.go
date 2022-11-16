package log

import (
	"context"

	goajwt "github.com/codeready-toolchain/sandbox-auth/goamiddleware/jwt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"goa.design/goa/v3/middleware"
)

// extractIdentityID obtains the identity ID out of the authentication context
func extractIdentityID(ctx context.Context) (string, error) {
	token := goajwt.ContextJWT(ctx)
	if token == nil {
		return "", errors.New("Missing token")
	}
	id := token.Claims.(jwt.MapClaims)["sub"]
	if id == nil {
		return "", errors.New("Missing sub")
	}

	return id.(string), nil
}

func ContextRequestID(ctx context.Context) (reqID string) {
	id := ctx.Value(middleware.RequestIDKey)
	if id != nil {
		reqID = id.(string)
	}
	return
}
