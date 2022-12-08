package factory

import (
	ctxpkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
)

type Manager struct {
	contextProducer ctxpkg.ServiceContextProducer
}

func NewManager(producer ctxpkg.ServiceContextProducer) *Manager {
	return &Manager{contextProducer: producer}
}

func (f *Manager) getContext() ctxpkg.ServiceContext {
	return f.contextProducer()
}
