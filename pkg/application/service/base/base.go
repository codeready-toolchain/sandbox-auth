package base

import (
	ctxpkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
)

// ServiceBase provides transaction control and other common features for service implementations
//
//nolint:all
type ServiceBase struct {
	ctxpkg.ServiceContext
}

// NewServiceBasee initializes a new ServiceBase
func NewServiceBasee(context ctxpkg.ServiceContext) ServiceBase {
	return ServiceBase{context}
}
