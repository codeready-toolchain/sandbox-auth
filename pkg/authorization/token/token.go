package token

import "crypto/rsa"

const (
	_ = iota

	// Token Statuses

	TOKEN_STATUS_DEPROVISIONED = 1
	TOKEN_STATUS_REVOKED       = 2
	TOKEN_STATUS_LOGGED_OUT    = 4
	TOKEN_STATUS_STALE         = 8

	TOKEN_TYPE_RPT     = "RPT"
	TOKEN_TYPE_ACCESS  = "ACC"
	TOKEN_TYPE_REFRESH = "REF"
)

// PrivateKey represents an RSA private key with a Key ID
type PrivateKey struct {
	KeyID string
	Key   *rsa.PrivateKey
}

// PublicKey represents an RSA public key with a Key ID
type PublicKey struct {
	KeyID string
	Key   *rsa.PublicKey
}

// JSONKeys the remote keys encoded in a json document
type JSONKeys struct {
	Keys []interface{} `json:"keys"`
}

// IsValidTokenType returns true if the specified token type is one of the known token types, otherwise returns false
func IsValidTokenType(tokenType string) bool {
	return tokenType == TOKEN_TYPE_RPT ||
		tokenType == TOKEN_TYPE_ACCESS ||
		tokenType == TOKEN_TYPE_REFRESH
}
