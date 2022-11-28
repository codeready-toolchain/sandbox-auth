package service

import (
	"context"
	account "github.com/codeready-toolchain/sandbox-auth/pkg/authentication/account/repository"
	"github.com/codeready-toolchain/sandbox-auth/pkg/authentication/provider"
	"github.com/gofrs/uuid"
)

const (
	FACTORY_TYPE_IDENTITY_PROVIDER = "factory.type.identity.provider"
)

/*
Steps for adding a new Service:
1. Add a new service interface to application/service/services.go
2. Create an implementation of the service interface
3. Add a new method to service.Services interface in application/service/services.go for accessing the service interface
   defined in step 1
4. Add a new method to application/service/factory/service_factory.go which implements the service access method
   from step #3 and uses the service constructor from step 2
5. Add a new method to gormapplication/application.go which implements the service access method from step #3
   and use the factory method from the step #4
*/

type AuthenticationProviderService interface {
	GenerateAuthCodeURL(ctx context.Context, redirect *string, apiClient *string,
		state *string, responseMode *string, referrer string, callbackURL string) (*string, error)
	LoginCallback(ctx context.Context, state string, code string, redirectURL string) (*string, error)
}

type LogoutService interface {
	Logout(ctx context.Context, redirectURL string) (string, error)
}

type UserService interface {
	LoadContextIdentityAndUser(ctx context.Context) (*account.Identity, error)
	CreateUser(ctx context.Context, username *string, email, fullName string, orgID uuid.UUID,
		serviceID *uuid.UUID, enabled bool) (*account.User, error)
	UpdateUser(ctx context.Context, userID, organizationID uuid.UUID, username *string,
		fullName, email string, serviceID *uuid.UUID, enabled bool) error
	UserInfo(ctx context.Context) (*account.User, error)
	LoadUser(ctx context.Context, userID uuid.UUID) (*account.User, error)
}

// Services creates instances of service layer objects
type Services interface {
	AuthenticationProviderService() AuthenticationProviderService
	LogoutService() LogoutService
	UserService() UserService
}

//----------------------------------------------------------------------------------------------------------------------
//
// Factories are a special type of service only accessible from other services, that can be replaced during testing,
// in order to produce mock / dummy factories
//
//----------------------------------------------------------------------------------------------------------------------

type IdentityProviderFactory interface {
	NewIdentityProvider(ctx context.Context, config provider.IdentityProviderConfiguration) provider.IdentityProvider
}

// Factories is the interface responsible for creating instances of factory objects
type Factories interface {
	IdentityProviderFactory() IdentityProviderFactory
}
