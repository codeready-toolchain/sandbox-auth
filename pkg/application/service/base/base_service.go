package base

import ctx "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"

// BaseService provides transaction control and other common features for service implementations
type BaseService struct {
	ctx.ServiceContext
}

// NewBaseService initializes a new BaseService
func NewBaseService(context ctx.ServiceContext) BaseService {
	return BaseService{context}
}
