package factory

import (
	ctxpkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
	"github.com/codeready-toolchain/sandbox-auth/pkg/configuration"
)

type Manager struct {
	contextProducer ctxpkg.ServiceContextProducer
	config          *configuration.Configuration
}

func NewManager(producer ctxpkg.ServiceContextProducer, config *configuration.Configuration) *Manager {
	return &Manager{contextProducer: producer, config: config}
}

func (f *Manager) getContext() ctxpkg.ServiceContext {
	return f.contextProducer()
}
