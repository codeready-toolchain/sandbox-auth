package factory

import (
	context2 "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
)

type Manager struct {
	contextProducer context2.ServiceContextProducer
}

func NewManager(producer context2.ServiceContextProducer) *Manager {
	return &Manager{contextProducer: producer}
}

func (f *Manager) getContext() context2.ServiceContext {
	return f.contextProducer()
}
