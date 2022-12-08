package context

import (
	repopkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/repository"
	svcpkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/service"
)

type ServiceContextProducer func() ServiceContext

type ServiceContext interface {
	Repositories() repopkg.Repositories
	Factories() svcpkg.Factories
	Services() svcpkg.Services
	ExecuteInTransaction(todo func() error) error
}
