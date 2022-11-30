package jwt

import (
	"context"
	jwt "github.com/dgrijalva/jwt-go"
)

type contextKey int

const (
	jwtKey contextKey = iota + 1
)

func WithJWT(ctx context.Context, t *jwt.Token) context.Context {
	return context.WithValue(ctx, jwtKey, t)
}

func ContextJWT(ctx context.Context) *jwt.Token {
	token, ok := ctx.Value(jwtKey).(*jwt.Token)
	if !ok {
		return nil
	}
	return token
}
