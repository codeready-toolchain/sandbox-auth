package factory

import (
	"context"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/service"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/service/base"
	servicecontext "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
	"github.com/codeready-toolchain/sandbox-auth/pkg/authentication/provider"
)

// NewIdentityProviderFactory returns the default Oauth provider factory.
func NewIdentityProviderFactory(context servicecontext.ServiceContext) service.IdentityProviderFactory {
	factory := &identityProviderFactoryImpl{
		BaseService: base.NewBaseService(context),
	}
	return factory
}

type identityProviderFactoryImpl struct {
	base.BaseService
}

// NewIdentityProvider creates a new identity provider based on the specified configuration
func (f *identityProviderFactoryImpl) NewIdentityProvider(ctx context.Context, config provider.IdentityProviderConfiguration) provider.IdentityProvider {
	return provider.NewIdentityProvider(config)
}
