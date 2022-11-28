package context

import (
	apprepo "github.com/codeready-toolchain/sandbox-auth/pkg/application/repository"
	svc "github.com/codeready-toolchain/sandbox-auth/pkg/application/service"
)

type ServiceContextProducer func() ServiceContext

type ServiceContext interface {
	Repositories() apprepo.Repositories
	Factories() svc.Factories
	Services() svc.Services
	ExecuteInTransaction(todo func() error) error
}
