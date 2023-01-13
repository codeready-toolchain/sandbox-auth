package repository

import authrepo "github.com/codeready-toolchain/sandbox-auth/pkg/authentication/repository"

type Repositories interface {
	IdentityRepository() authrepo.IdentityRepository
}
