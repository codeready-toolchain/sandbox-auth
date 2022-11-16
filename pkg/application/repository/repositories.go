package repository

import "github.com/codeready-toolchain/sandbox-auth/pkg/authentication/account/repository"

type Repositories interface {
	IdentityRepository() repository.IdentityRepository
}
