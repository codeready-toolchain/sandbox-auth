package factory

import (
	contextPkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
)

type Manager struct {
	contextProducer contextPkg.ServiceContextProducer
}

func NewManager(producer contextPkg.ServiceContextProducer) *Manager {
	return &Manager{contextProducer: producer}
}

func (f *Manager) getContext() contextPkg.ServiceContext {
	return f.contextProducer()
}
