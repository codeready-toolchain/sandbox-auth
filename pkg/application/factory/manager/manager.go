package factory

import (
	wrapper2 "github.com/codeready-toolchain/sandbox-auth/pkg/application/factory/wrapper"
	service2 "github.com/codeready-toolchain/sandbox-auth/pkg/application/service"
	context2 "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
	providerfactory "github.com/codeready-toolchain/sandbox-auth/pkg/authentication/provider/factory"
	"github.com/codeready-toolchain/sandbox-auth/pkg/configuration"
)

type WrapperDefinition interface {
	GetConstructor() wrapper2.FactoryWrapperConstructor
	GetInitializer() wrapper2.FactoryWrapperInitializer
}

type FactoryWrappers interface {
	RegisterWrapper(identifier string, constructor wrapper2.FactoryWrapperConstructor, initializer wrapper2.FactoryWrapperInitializer)
	GetWrapper(identifier string) WrapperDefinition
	ResetWrappers()
}

type wrapperDef struct {
	constructor wrapper2.FactoryWrapperConstructor
	initializer wrapper2.FactoryWrapperInitializer
}

func (d wrapperDef) GetConstructor() wrapper2.FactoryWrapperConstructor {
	return d.constructor
}

func (d wrapperDef) GetInitializer() wrapper2.FactoryWrapperInitializer {
	return d.initializer
}

type factoryWrappersImpl struct {
	wrappers map[string]wrapperDef
}

func NewFactoryWrappers() FactoryWrappers {
	return &factoryWrappersImpl{wrappers: make(map[string]wrapperDef)}
}

// disabledFactoryWrappers should be used when no wrapper support is desired, e.g. at normal runtime
type disabledFactoryWrappers struct{}

func (w *disabledFactoryWrappers) RegisterWrapper(identifier string, constructor wrapper2.FactoryWrapperConstructor, initializer wrapper2.FactoryWrapperInitializer) {
}
func (w *disabledFactoryWrappers) GetWrapper(identifier string) WrapperDefinition { return nil }
func (w *disabledFactoryWrappers) ResetWrappers()                                 {}

func NewDisabledFactoryWrappers() FactoryWrappers {
	return &disabledFactoryWrappers{}
}

func (w *factoryWrappersImpl) RegisterWrapper(identifier string, constructor wrapper2.FactoryWrapperConstructor, initializer wrapper2.FactoryWrapperInitializer) {
	w.wrappers[identifier] = wrapperDef{
		constructor: constructor,
		initializer: initializer,
	}
}

func (w *factoryWrappersImpl) GetWrapper(identifier string) WrapperDefinition {
	if def, ok := w.wrappers[identifier]; ok {
		return def
	}
	return nil
}

func (w *factoryWrappersImpl) ResetWrappers() {
	for k := range w.wrappers {
		delete(w.wrappers, k)
	}
}

type Manager struct {
	contextProducer context2.ServiceContextProducer
	config          *configuration.ConfigurationData
	wrappers        FactoryWrappers
}

func NewManager(producer context2.ServiceContextProducer, config *configuration.ConfigurationData, wrappers FactoryWrappers) *Manager {
	return &Manager{contextProducer: producer, config: config, wrappers: wrappers}
}

func (f *Manager) getContext() context2.ServiceContext {
	return f.contextProducer()
}

func (f *Manager) IdentityProviderFactory() service2.IdentityProviderFactory {
	def := f.wrappers.GetWrapper(service2.FACTORY_TYPE_IDENTITY_PROVIDER)

	if def != nil {
		// Create the wrapper first
		w := def.GetConstructor()(f.getContext(), f.config)

		// Initialize the wrapper
		if def.GetInitializer() != nil {
			def.GetInitializer()(w)
		}

		// Create the factory and set it in the wrapper
		w.SetFactory(providerfactory.NewIdentityProviderFactory(w.ServiceContext()))

		// Return the wrapper as the factory
		return w.(service2.IdentityProviderFactory)
	}

	return providerfactory.NewIdentityProviderFactory(f.getContext())
}
