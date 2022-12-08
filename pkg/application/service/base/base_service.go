package base

import (
	ctxpkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
)

// BaseService provides transaction control and other common features for service implementations
type BaseService struct {
	ctxpkg.ServiceContext
}

// NewBaseService initializes a new BaseService
func NewBaseService(context ctxpkg.ServiceContext) BaseService {
	return BaseService{context}
}
