package service

import (
	"context"

	"github.com/codeready-toolchain/sandbox-auth/pkg/application/service"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/service/base"
	servicecontext "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
	"github.com/codeready-toolchain/sandbox-auth/pkg/authentication/account/repository"
	provider2 "github.com/codeready-toolchain/sandbox-auth/pkg/authentication/provider"
	"github.com/codeready-toolchain/sandbox-auth/pkg/authorization/token/manager"
	"golang.org/x/oauth2"
	"net/url"
)

const (
	apiClientParam = "api_client"
	apiTokenParam  = "api_token"
	tokenJSONParam = "token_json"
)

type AuthenticationProviderServiceConfig interface {
	provider2.IdentityProviderConfiguration
	manager.TokenManagerConfiguration
	GetPublicOAuthClientID() string
}

func NewAuthenticationProviderService(ctx servicecontext.ServiceContext, config AuthenticationProviderServiceConfig) service.AuthenticationProviderService {
	return &authenticationProviderServiceImpl{
		BaseService: base.NewBaseService(ctx),
		config:      config,
	}
}

type authenticationProviderServiceImpl struct {
	base.BaseService
	config AuthenticationProviderServiceConfig
}

func (s *authenticationProviderServiceImpl) GenerateAuthCodeURL(ctx context.Context, redirect *string, apiClient *string,
	state *string, responseMode *string, referrer string, callbackURL string) (*string, error) {
	return nil, nil
}

func (s *authenticationProviderServiceImpl) LoginCallback(ctx context.Context, state string, code string, redirectURL string) (*string, error) {
	return nil, nil
}

// LoadReferrerAndResponseMode loads the referrer and responseMode from the stored values in the database
func (s *authenticationProviderServiceImpl) LoadReferrerAndResponseMode(ctx context.Context, state string) (string, *string, error) {
	return "", nil, nil
}

// ExchangeCodeWithProvider exchanges the specified code with the Authentication provider for an OAuth2 token
func (s *authenticationProviderServiceImpl) ExchangeCodeWithProvider(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error) {
	return nil, nil

}

// CreateOrUpdateIdentityAndUser creates or updates the user and identity associated with the oauth-provided user token,
// checks whether the user is approved, generates a new user token and returns a final URL to which the client should redirect
func (s *authenticationProviderServiceImpl) CreateOrUpdateIdentityAndUser(ctx context.Context, referrerURL *url.URL,
	providerToken *oauth2.Token) (*string, *oauth2.Token, *repository.User, error) {
	return nil, nil, nil, nil
}

// UpdateIdentityFromExistingIdentityInfo update identity if exists using profile information and returns updated identity.
func (s *authenticationProviderServiceImpl) UpdateIdentityUsingUserInfoEndPoint(ctx context.Context, accessToken string) (*repository.Identity, error) {
	return nil, nil
}
