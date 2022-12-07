package context

import (
	repositoryPkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/repository"
	servicePkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/service"
)

type ServiceContextProducer func() ServiceContext

type ServiceContext interface {
	Repositories() repositoryPkg.Repositories
	Factories() servicePkg.Factories
	Services() servicePkg.Services
	ExecuteInTransaction(todo func() error) error
}
