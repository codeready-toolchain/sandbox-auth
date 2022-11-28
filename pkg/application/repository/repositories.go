package repository

import (
	accountrepo "github.com/codeready-toolchain/sandbox-auth/pkg/authentication/account/repository"
)

type Repositories interface {
	IdentityRepository() accountrepo.IdentityRepository
	UserSessionRepository() accountrepo.UserSessionRepository
}
