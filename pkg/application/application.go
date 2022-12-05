package application

import (
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/repository"
	//"github.com/codeready-toolchain/sandbox-auth/pkg/application/service"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/transaction"
)

type Application interface {
	repository.Repositories
	//service.Services
	transaction.TransactionManager
}
