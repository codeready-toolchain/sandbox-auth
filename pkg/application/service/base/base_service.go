package base

import (
	contextPkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
)

// BaseService provides transaction control and other common features for service implementations
type BaseService struct {
	contextPkg.ServiceContext
}

// NewBaseService initializes a new BaseService
func NewBaseService(context contextPkg.ServiceContext) BaseService {
	return BaseService{context}
}
