package manager

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/oauth2"

	goam "github.com/codeready-toolchain/sandbox-auth/goamiddleware/jwt"

	"github.com/codeready-toolchain/sandbox-auth/pkg/application/repository"
	accountrepo "github.com/codeready-toolchain/sandbox-auth/pkg/authentication/account/repository"
	tokenpkg "github.com/codeready-toolchain/sandbox-auth/pkg/authorization/token"
	autherrors "github.com/codeready-toolchain/sandbox-auth/pkg/errors"
	"github.com/codeready-toolchain/sandbox-auth/pkg/log"
)

var defaultManager TokenManager
var defaultOnce sync.Once
var defaultErr error

const (
	//contextTokenManagerKey is a key that will be used to put and to get `tokenManager` from goa.context
	contextTokenManagerKey = iota
)

// DefaultManager creates the default manager if it has not created yet.
// This function must be called in main to make sure the default manager is created during service startup.
// It will try to create the default manager only once even if called multiple times.
func DefaultManager(repos repository.Repositories, config TokenManagerConfiguration) (TokenManager, error) {
	defaultOnce.Do(func() {
		defaultManager, defaultErr = NewTokenManager(repos, config)
	})
	return defaultManager, defaultErr
}

// TokenManagerConfiguration represents configuration needed to construct a token manager
type TokenManagerConfiguration interface {
	GetUserAccountPrivateKey() ([]byte, string)
	GetDevModePublicKey() (bool, []byte, string)
	IsPostgresDeveloperModeEnabled() bool
	GetAccessTokenExpiresIn() int64
	GetRefreshTokenExpiresIn() int64
}

// TokenClaims represents access token claims
type TokenClaims struct {
	Name          string `json:"name"`
	Username      string `json:"preferred_username"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Company       string `json:"company"`
	SessionState  string `json:"session_state"`
	Approved      bool   `json:"approved"`
	SessionID     string `json:"sid"`
	jwt.StandardClaims
}

// Permissions represents a "permissions" claim in the AuthorizationPayload
type Permissions struct {
	// ResourceSetName is the name of the resource
	ResourceSetName *string `json:"resource_set_name"`

	// ResourceSetID is the unique identifier for the resource
	ResourceSetID *string `json:"resource_set_id"`

	// Scopes indicates the granted scopes for the resource
	Scopes []string `json:"scopes"`
	Expiry int64    `json:"exp"`
}

// #####################################################################################################################
//
// Token sets
//
// #####################################################################################################################

// TokenSet represents a set of Access and Refresh tokens
type TokenSet struct {
	AccessToken      *string `json:"access_token,omitempty"`
	ExpiresIn        *int64  `json:"expires_in,omitempty"`
	NotBeforePolicy  *int64  `json:"not-before-policy,omitempty"`
	RefreshExpiresIn *int64  `json:"refresh_expires_in,omitempty"`
	RefreshToken     *string `json:"refresh_token,omitempty"`
	TokenType        *string `json:"token_type,omitempty"`
}

// ReadTokenSetFromJson parses json with a token set
func ReadTokenSetFromJson(ctx context.Context, jsonString string) (*TokenSet, error) {
	var token TokenSet
	err := json.Unmarshal([]byte(jsonString), &token)
	if err != nil {
		return nil, errors.Wrapf(err, "error when unmarshal json with access token %s ", jsonString)
	}
	return &token, nil
}

// #####################################################################################################################
//
// Context management
//
// #####################################################################################################################

// ContextIdentity returns the identity's ID found in given context
// Uses tokenManager.Locate to fetch the identity of currently logged in user
func ContextIdentity(ctx context.Context) (*uuid.UUID, error) {
	tm, err := ReadTokenManagerFromContext(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{}, "error reading token manager")

		return nil, errors.Wrapf(err, "error reading token manager")
	}
	// As mentioned in token.go, we can now safely convert tm to a token.Manager
	manager := tm.(TokenManager)
	uuid, err := manager.ExtractIdentityID(ctx)
	if err != nil {
		// TODO : need a way to define user as Guest
		log.Error(ctx, map[string]interface{}{
			"uuid": uuid,
			"err":  err,
		}, "identity belongs to a Guest User")

		return nil, errors.WithStack(err)
	}
	return &uuid, nil
}

// ContextWithTokenManager injects tokenManager in the context for every incoming request
// Accepts Token.Manager in order to make sure that correct object is set in the context.
// Only other possible value is nil
func ContextWithTokenManager(ctx context.Context, tm interface{}) context.Context {
	return context.WithValue(ctx, contextTokenManagerKey, tm)
}

// ReadTokenManagerFromContext extracts the token manager from the context and returns it
func ReadTokenManagerFromContext(ctx context.Context) (TokenManager, error) {
	tm := ctx.Value(contextTokenManagerKey)
	if tm == nil {
		log.Error(ctx, map[string]interface{}{
			"token": tm,
		}, "missing token manager")

		return nil, errors.New("missing token manager")
	}
	return tm.(*tokenManager), nil
}

// InjectTokenManager is a middleware responsible for setting up tokenManager in the context for every request.
func InjectTokenManager(tokenManager TokenManager) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			req := r
			req = r.WithContext(ContextWithTokenManager(r.Context(), tokenManager))
			h.ServeHTTP(rw, req)
		})
	}
}

// #####################################################################################################################
//
// Token Manager types and constructor
//
// #####################################################################################################################

// TokenManager generates and manages auth tokens
type TokenManager interface {
	Parse(ctx context.Context, tokenString string) (*jwt.Token, error)
	PublicKeys() []*rsa.PublicKey
	ExtractIdentityID(ctx context.Context) (uuid.UUID, error)
	ExtractSubject(ctx context.Context) (string, error)
	ParseToken(ctx context.Context, tokenString string) (*TokenClaims, error)
	ParseTokenWithMapClaims(ctx context.Context, tokenString string) (jwt.MapClaims, error)
	PublicKey(keyID string) *rsa.PublicKey
	JSONWebKeys() tokenpkg.JSONKeys
	PemKeys() tokenpkg.JSONKeys
	KeyFunction(context.Context) jwt.Keyfunc
	AuthServiceAccountToken() string
	GenerateServiceAccountToken(saID string, saName string) (string, error)
	GenerateUnsignedServiceAccountToken(saID string, saName string) *jwt.Token
	GenerateUserTokenForAPIClient(ctx context.Context, providerToken oauth2.Token) (*oauth2.Token, error)
	GenerateUserTokenForIdentity(ctx context.Context, identity accountrepo.Identity, userSessionID uuid.UUID, offlineToken bool) (*oauth2.Token, error)
	GenerateUserTokenUsingRefreshToken(ctx context.Context, refreshTokenString string, identity *accountrepo.Identity, permissions []Permissions) (*oauth2.Token, error)
	SignHashWithPrivateKey(hash []byte) ([]byte, error)
	ConvertTokenSet(tokenSet TokenSet) *oauth2.Token
	ConvertToken(oauthToken oauth2.Token) (*TokenSet, error)
	AddLoginRequiredHeaderToUnauthorizedError(err error, rw http.ResponseWriter)
	AddLoginRequiredHeader(rw http.ResponseWriter)
}

type tokenManager struct {
	publicKeysMap            map[string]*rsa.PublicKey
	publicKeys               []*tokenpkg.PublicKey
	serviceAccountPrivateKey *tokenpkg.PrivateKey
	userAccountPrivateKey    *tokenpkg.PrivateKey
	jsonWebKeys              tokenpkg.JSONKeys
	pemKeys                  tokenpkg.JSONKeys
	serviceAccountToken      string
	config                   TokenManagerConfiguration
	repos                    repository.Repositories
}

// NewTokenManager returns a new token Manager for handling tokens
func NewTokenManager(repos repository.Repositories, config TokenManagerConfiguration) (TokenManager, error) {
	tm := &tokenManager{
		repos:         repos,
		publicKeysMap: map[string]*rsa.PublicKey{},
	}
	tm.config = config

	// Load the user account private key and add it to the manager.
	// Extract the public key from it and add it to the map of public keys.
	var err error
	key, kid := config.GetUserAccountPrivateKey()
	tm.userAccountPrivateKey, err = tm.loadPrivateKey(tm, key, kid)
	if err != nil {
		log.Error(nil, map[string]interface{}{"err": err}, "unable to load user account private keys")
		return nil, err
	}

	// Load Keycloak public key if run in dev mode.
	devMode, key, kid := config.GetDevModePublicKey()
	if devMode {
		rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
		if err != nil {
			log.Error(nil, map[string]interface{}{"err": err}, "unable to load dev mode public key")
			return nil, err
		}
		tm.publicKeysMap[kid] = rsaKey
		tm.publicKeys = append(tm.publicKeys, &tokenpkg.PublicKey{KeyID: kid, Key: rsaKey})
		log.Info(nil, map[string]interface{}{"kid": kid}, "dev mode public key added")
	}

	// Convert public keys to JWK format
	jsonWebKeys, err := tm.toJSONWebKeys(tm.publicKeys)
	if err != nil {
		log.Error(nil, map[string]interface{}{"err": err}, "unable to convert public keys to JSON Web Keys")
		return nil, errors.New("unable to convert public keys to JSON Web Keys")
	}
	tm.jsonWebKeys = jsonWebKeys

	// Convert public keys to PEM format
	jsonKeys, err := tm.toPemKeys(tm.publicKeys)
	if err != nil {
		log.Error(nil, map[string]interface{}{"err": err}, "unable to convert public keys to PEM Keys")
		return nil, errors.New("unable to convert public keys to PEM Keys")
	}
	tm.pemKeys = jsonKeys

	return tm, nil
}

// #####################################################################################################################
//
// Service Account functions (Service accounts are special non-user accounts used by other services)
//
// #####################################################################################################################

// GenerateServiceAccountToken generates and signs a new Service Account Token (Protection API Token)
func (m *tokenManager) GenerateServiceAccountToken(saID string, saName string) (string, error) {
	token := m.GenerateUnsignedServiceAccountToken(saID, saName)
	tokenStr, err := token.SignedString(m.serviceAccountPrivateKey.Key)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return tokenStr, nil
}

// GenerateUnsignedServiceAccountToken generates an unsigned Service Account Token (Protection API Token)
func (m *tokenManager) GenerateUnsignedServiceAccountToken(saID string, saName string) *jwt.Token {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = m.serviceAccountPrivateKey.KeyID
	claims := token.Claims.(jwt.MapClaims)
	claims["service_accountname"] = saName
	claims["sub"] = saID
	claims["jti"] = uuid.Must(uuid.NewV4()).String()
	claims["iat"] = time.Now().Unix()
	claims["scopes"] = []string{"uma_protection"}
	return token
}

// AuthServiceAccountToken returns the service account token which authenticates the Auth service
func (m *tokenManager) AuthServiceAccountToken() string {
	return m.serviceAccountToken
}

// #####################################################################################################################
//
// User Token functions (User tokens are an oauth2 token consisting of an access token, refresh token and signature
//
// #####################################################################################################################

// GenerateUserTokenForIdentity generates an OAuth2 user token for the given identity
func (m *tokenManager) GenerateUserTokenForIdentity(ctx context.Context, identity accountrepo.Identity, userSessionID uuid.UUID, offlineToken bool) (*oauth2.Token, error) {
	nowTime := time.Now().Unix()
	unsignedAccessToken, err := m.GenerateUnsignedUserAccessTokenForIdentity(ctx, identity, userSessionID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	accessToken, err := unsignedAccessToken.SignedString(m.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	unsignedRefreshToken, err := m.GenerateUnsignedUserRefreshTokenForIdentity(ctx, identity, userSessionID, offlineToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	refreshToken, err := unsignedRefreshToken.SignedString(m.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var nbf int64

	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       time.Unix(nowTime+m.config.GetAccessTokenExpiresIn(), 0),
		TokenType:    "Bearer",
	}

	// Derivative OAuth2 claims "expires_in" and "refresh_expires_in"
	extra := make(map[string]interface{})
	extra["expires_in"] = m.config.GetAccessTokenExpiresIn()
	extra["refresh_expires_in"] = m.config.GetRefreshTokenExpiresIn()
	extra["not_before_policy"] = nbf

	token = token.WithExtra(extra)

	return token, nil
}

func (m *tokenManager) SignHashWithPrivateKey(hash []byte) ([]byte, error) {
	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPSS(rand.Reader, m.userAccountPrivateKey.Key, crypto.SHA256, hash, nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// #####################################################################################################################
//
// Access Token functions (Access tokens are trusted tokens used to identify a user)
//
// #####################################################################################################################

// GenerateUnsignedUserAccessTokenFromClaims generates a new token based on the specified claims
func (m *tokenManager) GenerateUnsignedUserAccessTokenFromClaims(ctx context.Context, tokenClaims *TokenClaims,
	identity *accountrepo.Identity) (*jwt.Token, error) {

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = m.userAccountPrivateKey.KeyID

	claims := token.Claims.(jwt.MapClaims)

	var err error
	jtiUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims["jti"] = jtiUUID.String()

	claims["exp"] = tokenClaims.ExpiresAt
	claims["nbf"] = tokenClaims.NotBefore
	claims["iat"] = tokenClaims.IssuedAt
	claims["iss"] = tokenClaims.Issuer
	claims["aud"] = tokenClaims.Audience
	claims["typ"] = "Bearer"
	claims["auth_time"] = tokenClaims.IssuedAt
	claims["approved"] = identity != nil && tokenClaims.Approved

	if identity != nil {
		claims["sub"] = identity.IdentityID.String()
		claims["preferred_username"] = identity.Username
	} else {
		claims["sub"] = tokenClaims.Subject
		claims["email_verified"] = tokenClaims.EmailVerified
		claims["name"] = tokenClaims.Name
		claims["preferred_username"] = tokenClaims.Username
		claims["given_name"] = tokenClaims.GivenName
		claims["family_name"] = tokenClaims.FamilyName
		claims["email"] = tokenClaims.Email
	}

	claims["azp"] = tokenClaims.Audience
	claims["session_state"] = tokenClaims.SessionState
	claims["acr"] = "0"

	realmAccess := make(map[string]interface{})
	realmAccess["roles"] = []string{"uma_authorization"}
	claims["realm_access"] = realmAccess

	claims["sid"] = tokenClaims.SessionID

	return token, nil
}

// GenerateUnsignedUserAccessTokenForIdentity generates an unsigned OAuth2 user access token for the given identity
func (m *tokenManager) GenerateUnsignedUserAccessTokenForIdentity(ctx context.Context, identity accountrepo.Identity,
	userSessionID uuid.UUID) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = m.userAccountPrivateKey.KeyID

	claims := token.Claims.(jwt.MapClaims)

	var err error
	jtiUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims["jti"] = jtiUUID.String()

	iat := time.Now().Unix()
	claims["exp"] = iat + m.config.GetAccessTokenExpiresIn()
	claims["nbf"] = 0
	claims["iat"] = iat
	claims["typ"] = "Bearer"
	claims["auth_time"] = iat // TODO should use the time when user actually logged-in the last time. Will need to get this time from the provider token
	claims["sub"] = identity.IdentityID.String()
	claims["preferred_username"] = identity.Username
	claims["sid"] = userSessionID.String()

	ssUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims["session_state"] = ssUUID.String()

	return token, nil
}

// #####################################################################################################################
//
// Refresh token functions (refresh tokens are used to obtain a new user token)
//
// #####################################################################################################################

// GenerateUnsignedUserRefreshTokenForIdentity generates an unsigned OAuth2 user refresh token for the given identity
func (m *tokenManager) GenerateUnsignedUserRefreshTokenForIdentity(ctx context.Context, identity accountrepo.Identity,
	userSessionID uuid.UUID, offlineToken bool) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = m.userAccountPrivateKey.KeyID

	claims := token.Claims.(jwt.MapClaims)

	var err error
	jtiUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims["jti"] = jtiUUID.String()

	iat := time.Now().Unix()
	var exp int64 // Offline tokens do not expire
	typ := "Offline"
	if !offlineToken {
		exp = iat + m.config.GetRefreshTokenExpiresIn()
		typ = "Refresh"
	}
	claims["exp"] = exp
	claims["nbf"] = 0
	claims["iat"] = iat
	claims["typ"] = typ
	claims["auth_time"] = 0
	claims["sub"] = identity.IdentityID.String()
	claims["sid"] = userSessionID.String()

	ssUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims["session_state"] = ssUUID.String()

	return token, nil
}

// TODO combine this with GenerateUnsignedUserRefreshTokenForIdentity, make previous refreshToken parameter optional
// GenerateUnsignedUserRefreshToken generates an unsigned OAuth2 user refresh token for the given identity based on the provided refresh token
func (m *tokenManager) GenerateUnsignedUserRefreshToken(ctx context.Context, refreshToken string,
	identity *accountrepo.Identity) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = m.userAccountPrivateKey.KeyID

	oldClaims, err := m.ParseToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims := token.Claims.(jwt.MapClaims)

	jtiUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims["jti"] = jtiUUID.String()

	iat := time.Now().Unix()
	var exp int64 // Offline tokens do not expire
	typ := "Offline"
	if oldClaims.ExpiresAt != 0 {
		exp = iat + m.config.GetRefreshTokenExpiresIn()
		typ = "Refresh"
	}
	claims["exp"] = exp
	claims["nbf"] = 0
	claims["iat"] = iat
	claims["typ"] = typ
	claims["auth_time"] = 0
	claims["sid"] = oldClaims.SessionID

	if identity != nil {
		claims["sub"] = identity.IdentityID.String()
	} else {
		// populate claims for user details in refresh token for api_client as we don't have identity in db for it
		claims["sub"] = oldClaims.Subject
		claims["email_verified"] = oldClaims.EmailVerified
		claims["name"] = oldClaims.Name
		claims["preferred_username"] = oldClaims.Username
		claims["given_name"] = oldClaims.GivenName
		claims["family_name"] = oldClaims.FamilyName
		claims["email"] = oldClaims.Email
	}

	claims["azp"] = oldClaims.Audience
	claims["session_state"] = oldClaims.SessionState

	return token, nil
}

// GenerateUnsignedUserAccessTokenFromRefreshToken
func (m *tokenManager) GenerateUnsignedUserAccessTokenFromRefreshToken(ctx context.Context, refreshTokenString string,
	identity *accountrepo.Identity) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = m.userAccountPrivateKey.KeyID

	refreshTokenClaims, err := m.ParseToken(ctx, refreshTokenString)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims := token.Claims.(jwt.MapClaims)

	jtiUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims["jti"] = jtiUUID.String()

	iat := time.Now().Unix()
	claims["exp"] = iat + m.config.GetAccessTokenExpiresIn()
	claims["nbf"] = 0
	claims["iat"] = iat
	claims["typ"] = "Bearer"
	claims["auth_time"] = iat
	claims["approved"] = identity != nil
	claims["sid"] = refreshTokenClaims.SessionID
	if identity != nil {
		claims["sub"] = identity.IdentityID.String()
		claims["preferred_username"] = identity.Username
	} else {
		claims["sub"] = refreshTokenClaims.Subject

		// refresh token should have all following claims included only for api_client(e.g. vscode analytics) who don't have identity in auth db
		claims["email_verified"] = refreshTokenClaims.EmailVerified
		claims["name"] = refreshTokenClaims.Name
		claims["preferred_username"] = refreshTokenClaims.Username
		claims["given_name"] = refreshTokenClaims.GivenName
		claims["family_name"] = refreshTokenClaims.FamilyName
		claims["email"] = refreshTokenClaims.Email
		claims["company"] = refreshTokenClaims.Company
	}

	claims["azp"] = refreshTokenClaims.Audience
	claims["session_state"] = refreshTokenClaims.SessionState
	claims["acr"] = "0"

	realmAccess := make(map[string]interface{})
	realmAccess["roles"] = []string{"uma_authorization"}
	claims["realm_access"] = realmAccess

	return token, nil
}

// GenerateUserTokenUsingRefreshToken
func (m *tokenManager) GenerateUserTokenUsingRefreshToken(ctx context.Context, refreshTokenString string,
	identity *accountrepo.Identity, permissions []Permissions) (*oauth2.Token, error) {

	nowTime := time.Now().Unix()
	unsignedAccessToken, err := m.GenerateUnsignedUserAccessTokenFromRefreshToken(ctx, refreshTokenString, identity)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if permissions != nil && len(permissions) > 0 {
		claims := unsignedAccessToken.Claims.(jwt.MapClaims)
		claims["permissions"] = permissions
	}

	accessToken, err := unsignedAccessToken.SignedString(m.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	unsignedRefreshToken, err := m.GenerateUnsignedUserRefreshToken(ctx, refreshTokenString, identity)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	refreshToken, err := unsignedRefreshToken.SignedString(m.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var nbf int64

	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       time.Unix(nowTime+m.config.GetAccessTokenExpiresIn(), 0),
		TokenType:    "Bearer",
	}

	// Derivative OAuth2 claims "expires_in" and "refresh_expires_in"
	extra := make(map[string]interface{})
	extra["expires_in"] = m.config.GetAccessTokenExpiresIn()
	extra["refresh_expires_in"] = m.config.GetRefreshTokenExpiresIn()
	extra["not_before_policy"] = nbf

	token = token.WithExtra(extra)

	return token, nil
}

// #####################################################################################################################
//
// APIClient functions
//
// #####################################################################################################################

// GenerateUserTokenForAPIClient
func (m *tokenManager) GenerateUserTokenForAPIClient(ctx context.Context, providerToken oauth2.Token) (*oauth2.Token, error) {
	unsignedAccessToken, err := m.GenerateUnsignedUserAccessTokenForAPIClient(ctx, providerToken.AccessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	accessToken, err := unsignedAccessToken.SignedString(m.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	unsignedRefreshToken, err := m.GenerateUnsignedUserRefreshTokenForAPIClient(ctx, providerToken.AccessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	refreshToken, err := unsignedRefreshToken.SignedString(m.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       providerToken.Expiry,
		TokenType:    "Bearer",
	}

	// Derivative OAuth2 claims "expires_in" and "refresh_expires_in"
	extra := make(map[string]interface{})
	expiresIn := providerToken.Extra("expires_in")
	if expiresIn != nil {
		extra["expires_in"] = expiresIn
	}
	refreshExpiresIn := providerToken.Extra("refresh_expires_in")
	if refreshExpiresIn != nil {
		extra["refresh_expires_in"] = refreshExpiresIn
	}
	notBeforePolicy := providerToken.Extra("not_before_policy")
	if notBeforePolicy != nil {
		extra["not_before_policy"] = notBeforePolicy
	}
	if len(extra) > 0 {
		token = token.WithExtra(extra)
	}

	return token, nil
}

// GenerateUnsignedUserAccessTokenForAPIClient generates an unsigned OAuth2 user access token for the api_client based on the Keycloak token
func (m *tokenManager) GenerateUnsignedUserAccessTokenForAPIClient(ctx context.Context, providerAccessToken string) (*jwt.Token, error) {
	kcClaims, err := m.ParseToken(ctx, providerAccessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return m.GenerateUnsignedUserAccessTokenFromClaimsForAPIClient(ctx, kcClaims)
}

// GenerateUnsignedUserAccessTokenFromClaimsForAPIClient generates a new token based on the specified claims for api_client
func (m *tokenManager) GenerateUnsignedUserAccessTokenFromClaimsForAPIClient(ctx context.Context,
	tokenClaims *TokenClaims) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = m.userAccountPrivateKey.KeyID

	claims := token.Claims.(jwt.MapClaims)

	var err error
	jtiUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims["jti"] = jtiUUID.String()

	iat := time.Now().Unix()
	claims["exp"] = iat + m.config.GetAccessTokenExpiresIn()
	claims["nbf"] = 0
	claims["iat"] = iat
	//claims["iss"] = authOpenshiftIO
	//claims["aud"] = openshiftIO
	claims["typ"] = "Bearer"
	claims["auth_time"] = iat
	claims["typ"] = "Bearer"
	claims["approved"] = tokenClaims.Approved

	claims["sub"] = tokenClaims.Subject
	claims["email_verified"] = tokenClaims.EmailVerified
	claims["name"] = tokenClaims.Name
	claims["preferred_username"] = tokenClaims.Username
	claims["given_name"] = tokenClaims.GivenName
	claims["family_name"] = tokenClaims.FamilyName
	claims["email"] = tokenClaims.Email
	claims["azp"] = tokenClaims.Audience
	claims["session_state"] = tokenClaims.SessionState
	claims["acr"] = "0"

	realmAccess := make(map[string]interface{})
	realmAccess["roles"] = []string{"uma_authorization"}
	claims["realm_access"] = realmAccess

	return token, nil
}

// GenerateUnsignedUserRefreshToken generates an unsigned OAuth2 user refresh token for the given identity based on the Keycloak token
func (m *tokenManager) GenerateUnsignedUserRefreshTokenForAPIClient(ctx context.Context, accessToken string) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = m.userAccountPrivateKey.KeyID

	tokenClaims, err := m.ParseToken(ctx, accessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims := token.Claims.(jwt.MapClaims)

	jtiUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims["jti"] = jtiUUID.String()

	iat := time.Now().Unix()
	exp := iat + m.config.GetRefreshTokenExpiresIn()
	typ := "Refresh"
	claims["exp"] = exp
	claims["nbf"] = 0
	claims["iat"] = iat
	claims["typ"] = typ
	claims["auth_time"] = 0
	claims["sub"] = tokenClaims.Subject
	claims["email_verified"] = tokenClaims.EmailVerified
	claims["name"] = tokenClaims.Name
	claims["preferred_username"] = tokenClaims.Username
	claims["given_name"] = tokenClaims.GivenName
	claims["family_name"] = tokenClaims.FamilyName
	claims["email"] = tokenClaims.Email
	claims["azp"] = tokenClaims.Audience
	claims["session_state"] = tokenClaims.SessionState

	return token, nil
}

// #####################################################################################################################
//
// General functions
//
// #####################################################################################################################

// JSONWebKeys returns all the public keys in JSON Web Keys format
func (mgm *tokenManager) JSONWebKeys() tokenpkg.JSONKeys {
	return mgm.jsonWebKeys
}

// KeyFunction returns a function that can be used to extract the key ID (kid) claim value from a JWT token
func (m *tokenManager) KeyFunction(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"]
		if kid == nil {
			log.Error(ctx, map[string]interface{}{}, "There is no 'kid' header in the token")
			return nil, errors.New("There is no 'kid' header in the token")
		}
		key := m.PublicKey(fmt.Sprintf("%s", kid))
		if key == nil {
			log.Error(ctx, map[string]interface{}{
				"kid": kid,
			}, "There is no public key with such ID")
			return nil, errors.New(fmt.Sprintf("There is no public key with such ID: %s", kid))
		}
		return key, nil
	}
}

// ExtractIdentityID extracts the "sub" claim from the JWT token in the specified token and returns it as a UUID.  The
// UUID value typically represents the Identity ID of the current user.
func (m *tokenManager) ExtractIdentityID(ctx context.Context) (uuid.UUID, error) {
	token := goam.ContextJWT(ctx)
	if token == nil {
		return uuid.UUID{}, errors.New("Missing token")
	}
	id := token.Claims.(jwt.MapClaims)["sub"]
	if id == nil {
		return uuid.UUID{}, errors.New("Missing sub")
	}
	idTyped, err := uuid.FromString(id.(string))
	if err != nil {
		return uuid.UUID{}, errors.New("uuid not of type string")
	}
	return idTyped, nil
}

func (m *tokenManager) ExtractSubject(ctx context.Context) (string, error) {
	token := goam.ContextJWT(ctx)
	if token == nil {
		return "", errors.New("Missing token")
	}
	id := token.Claims.(jwt.MapClaims)["sub"]
	if id == nil {
		return "", errors.New("Missing sub")
	}
	return id.(string), nil
}

// Parse parses the specified token string and returns a JWT token
func (m *tokenManager) Parse(ctx context.Context, tokenString string) (*jwt.Token, error) {
	keyFunc := m.KeyFunction(ctx)
	jwtToken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to parse token")
		return nil, autherrors.NewUnauthorizedError(err.Error())
	}

	claims := jwtToken.Claims.(jwt.MapClaims)
	sid, found := claims["sid"]
	if found {
		userSessionID, err := uuid.FromString(sid.(string))
		if err != nil {
			return nil, errors.New("invalid session identifier [sid] in token claims - not a uuid")
		}

		userSession, err := m.repos.UserSessionRepository().Load(ctx, userSessionID)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("error loading user session for sid [%s]", userSessionID.String()))
		}

		if userSession.SessionTerminated != nil {
			return nil, errors.New("session terminated")
		}
	}

	return jwtToken, nil
}

// ParseToken parses the specified token string and returns its claims
func (m *tokenManager) ParseToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, m.KeyFunction(ctx))
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(*TokenClaims)
	if token.Valid {
		return claims, nil
	}
	return nil, errors.WithStack(errors.New("token is not valid"))
}

// ParseTokenWithMapClaims parses token claims
func (m *tokenManager) ParseTokenWithMapClaims(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, m.KeyFunction(ctx))
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(jwt.MapClaims)
	if token.Valid {
		return claims, nil
	}
	return nil, errors.WithStack(errors.New("token is not valid"))
}

// PemKeys returns all the public keys in PEM-like format (PEM without header and footer)
func (m *tokenManager) PemKeys() tokenpkg.JSONKeys {
	return m.pemKeys
}

// PublicKey returns the public key by the ID
func (m *tokenManager) PublicKey(keyID string) *rsa.PublicKey {
	return m.publicKeysMap[keyID]
}

// PublicKeys returns all the public keys
func (m *tokenManager) PublicKeys() []*rsa.PublicKey {
	keys := make([]*rsa.PublicKey, 0, len(m.publicKeysMap))
	for _, key := range m.publicKeys {
		keys = append(keys, key.Key)
	}
	return keys
}

// ConvertToken converts the oauth2.Token to a token set
func (m *tokenManager) ConvertToken(oauthToken oauth2.Token) (*TokenSet, error) {

	tokenSet := &TokenSet{
		AccessToken:  &oauthToken.AccessToken,
		RefreshToken: &oauthToken.RefreshToken,
		TokenType:    &oauthToken.TokenType,
	}

	var err error
	tokenSet.ExpiresIn, err = m.extraInt(oauthToken, "expires_in")
	if err != nil {
		return nil, err
	}
	tokenSet.RefreshExpiresIn, err = m.extraInt(oauthToken, "refresh_expires_in")
	if err != nil {
		return nil, err
	}
	tokenSet.NotBeforePolicy, err = m.extraInt(oauthToken, "not_before_policy")
	if err != nil {
		return nil, err
	}

	return tokenSet, nil
}

// ConvertTokenSet converts the token set to oauth2.Token
func (m *tokenManager) ConvertTokenSet(tokenSet TokenSet) *oauth2.Token {
	var accessToken, refreshToken, tokenType string
	extra := make(map[string]interface{})
	if tokenSet.AccessToken != nil {
		accessToken = *tokenSet.AccessToken
	}
	if tokenSet.RefreshToken != nil {
		refreshToken = *tokenSet.RefreshToken
	}
	if tokenSet.TokenType != nil {
		tokenType = *tokenSet.TokenType
	}
	var expire time.Time
	if tokenSet.ExpiresIn != nil {
		expire = time.Now().Add(time.Duration(*tokenSet.ExpiresIn) * time.Second)
		extra["expires_in"] = *tokenSet.ExpiresIn
	}
	if tokenSet.RefreshExpiresIn != nil {
		extra["refresh_expires_in"] = *tokenSet.RefreshExpiresIn
	}
	if tokenSet.NotBeforePolicy != nil {
		extra["not_before_policy"] = *tokenSet.NotBeforePolicy
	}

	oauth2Token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		Expiry:       expire,
	}
	oauth2Token = oauth2Token.WithExtra(extra)

	return oauth2Token
}

// AddLoginRequiredHeader adds "WWW-Authenticate: LOGIN" header to the response
func (m *tokenManager) AddLoginRequiredHeader(rw http.ResponseWriter) {
	rw.Header().Add("Access-Control-Expose-Headers", "WWW-Authenticate")
	//loginURL := m.config.GetAuthServiceURL() + authclient.LoginLoginPath()
	//rw.Header().Set("WWW-Authenticate", fmt.Sprintf("LOGIN url=%s, description=\"re-login is required\"", loginURL))
}

// AddLoginRequiredHeaderToUnauthorizedError adds "WWW-Authenticate: LOGIN" header to the response
// if the error is UnauthorizedError
func (m *tokenManager) AddLoginRequiredHeaderToUnauthorizedError(err error, rw http.ResponseWriter) {
	if unth, _ := autherrors.IsUnauthorizedError(err); unth {
		m.AddLoginRequiredHeader(rw)
	}
}

// #####################################################################################################################
//
// Private utility functions
//
// #####################################################################################################################

// extraInt
func (m *tokenManager) extraInt(oauthToken oauth2.Token, claimName string) (*int64, error) {
	claim := oauthToken.Extra(claimName)
	if claim != nil {
		claimInt, err := NumberToInt(claim)
		if err != nil {
			return nil, err
		}
		return &claimInt, nil
	}
	return nil, nil
}

// LoadPrivateKey loads a private key and a deprecated private key.
// Extracts public keys from them and adds them to the manager
// Returns the loaded private key.
func (m *tokenManager) loadPrivateKey(tm *tokenManager, key []byte, kid string) (*tokenpkg.PrivateKey, error) {
	if len(key) == 0 || kid == "" {
		log.Error(nil, map[string]interface{}{
			"kid":        kid,
			"key_length": len(key),
		}, "private key or its ID are not set up")
		return nil, errors.New("private key or its ID are not set up")
	}

	// Load the private key. Extract the public key from it
	rsaServiceAccountKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		log.Error(nil, map[string]interface{}{"err": err}, "unable to parse private key")
		return nil, err
	}
	privateKey := &tokenpkg.PrivateKey{KeyID: kid, Key: rsaServiceAccountKey}
	pk := &rsaServiceAccountKey.PublicKey
	tm.publicKeysMap[kid] = pk
	tm.publicKeys = append(tm.publicKeys, &tokenpkg.PublicKey{KeyID: kid, Key: pk})
	log.Info(nil, map[string]interface{}{"kid": kid}, "public key added")

	return privateKey, nil
}

func (m *tokenManager) toJSONWebKeys(publicKeys []*tokenpkg.PublicKey) (tokenpkg.JSONKeys, error) {
	var result []interface{}
	for _, key := range publicKeys {
		jwkey := jose.JSONWebKey{Key: key.Key, KeyID: key.KeyID, Algorithm: "RS256", Use: "sig"}
		keyData, err := jwkey.MarshalJSON()
		if err != nil {
			return tokenpkg.JSONKeys{}, err
		}
		var raw interface{}
		err = json.Unmarshal(keyData, &raw)
		if err != nil {
			return tokenpkg.JSONKeys{}, err
		}
		result = append(result, raw)
	}
	return tokenpkg.JSONKeys{Keys: result}, nil
}

func (m *tokenManager) toPemKeys(publicKeys []*tokenpkg.PublicKey) (tokenpkg.JSONKeys, error) {
	var pemKeys []interface{}
	for _, key := range publicKeys {
		keyData, err := m.toPem(key.Key)
		if err != nil {
			return tokenpkg.JSONKeys{}, err
		}
		rawPemKey := map[string]interface{}{"kid": key.KeyID, "key": keyData}
		pemKeys = append(pemKeys, rawPemKey)
	}
	return tokenpkg.JSONKeys{Keys: pemKeys}, nil
}

func (m *tokenManager) toPem(key *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pubASN1), nil
}

// NumberToInt convert interface{} to int64
func NumberToInt(number interface{}) (int64, error) {
	switch v := number.(type) {
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case float32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	}
	result, err := strconv.ParseInt(fmt.Sprintf("%v", number), 10, 64)
	if err != nil {
		return 0, err
	}
	return result, nil
}

// CheckClaims checks if all the required claims are present in the access token
func CheckClaims(claims *TokenClaims) error {
	if claims.Subject == "" {
		return errors.New("subject claim not found in token")
	}
	_, err := uuid.FromString(claims.Subject)
	if err != nil {
		return errors.New("subject claim from token is not UUID " + err.Error())
	}
	if claims.Username == "" {
		return errors.New("username claim not found in token")
	}
	if claims.Email == "" {
		return errors.New("email claim not found in token")
	}
	return nil
}
