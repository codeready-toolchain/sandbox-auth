package factory

import (
	"context"
	"github.com/codeready-toolchain/sandbox-auth/pkg/configuration"
	"time"

	factory "github.com/codeready-toolchain/sandbox-auth/pkg/application/factory/manager"
	repopkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/repository"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/service"
	svcContext "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
	transpkg "github.com/codeready-toolchain/sandbox-auth/pkg/application/transaction"

	"github.com/codeready-toolchain/sandbox-auth/pkg/log"

	"github.com/pkg/errors"
)

type serviceContextImpl struct {
	repositories              repopkg.Repositories
	transactionalRepositories repopkg.Repositories
	transactionManager        transpkg.Manager
	inTransaction             bool
	services                  service.Services
	factories                 service.Factories
}

func NewServiceContext(repos repopkg.Repositories, tm transpkg.Manager, config *configuration.Configuration,
	options ...Option) svcContext.ServiceContext {
	ctx := &serviceContextImpl{}
	ctx.repositories = repos
	ctx.transactionManager = tm
	ctx.inTransaction = false

	sc := ctx
	ctx.factories = factory.NewManager(func() svcContext.ServiceContext { return sc }, config)
	ctx.services = NewServiceFactory(func() svcContext.ServiceContext { return sc }, config, options...)
	return sc
}

func (s *serviceContextImpl) Repositories() repopkg.Repositories {
	if s.inTransaction {
		return s.transactionalRepositories
	}
	return s.repositories
}

func (s *serviceContextImpl) Factories() service.Factories {
	return s.factories
}

func (s *serviceContextImpl) Services() service.Services {
	return s.services
}

func (s *serviceContextImpl) ExecuteInTransaction(todo func() error) error {
	if !s.inTransaction {
		// If we are not in a transaction already, start a new transaction
		var tx transpkg.Transaction
		var err error
		if tx, err = s.transactionManager.BeginTransaction(); err != nil {
			log.Error(context.TODO(), map[string]interface{}{
				"err": err,
			}, "database BeginTransaction failed!")

			return errors.WithStack(err)
		}

		// Set the transaction flag to true
		s.inTransaction = true

		// Set the transactional repositories property
		s.transactionalRepositories = tx.(repopkg.Repositories)

		defer s.endTransaction()

		return func() error {
			errorChan := make(chan error, 1)
			txTimeout := time.After(transpkg.DatabaseTransactionTimeout())

			go func() {
				defer func() {
					if err := recover(); err != nil {
						errorChan <- errors.Errorf("Unknown error: %v", err)
					}
				}()
				errorChan <- todo()
			}()

			select {
			case err := <-errorChan:
				if err != nil {
					log.Debug(context.TODO(), nil, "Rolling back the transaction...")
					err = tx.Rollback()
					if err != nil {
						log.Error(context.TODO(), map[string]interface{}{
							"err": err,
						}, "error rolling back transaction")
					}
					log.Error(context.TODO(), map[string]interface{}{
						"err": err,
					}, "database transaction failed!")
					return errors.WithStack(err)
				}

				err = tx.Commit()
				if err != nil {
					log.Error(context.TODO(), map[string]interface{}{
						"err": err,
					}, "database commit failed")
				}
				log.Debug(context.TODO(), nil, "Commit the transaction!")
				return nil
			case <-txTimeout:
				log.Debug(context.TODO(), nil, "Rolling back the transaction...")
				err = tx.Rollback()
				if err != nil {
					log.Error(context.TODO(), nil, "database rollback failed")
				}
				log.Error(context.TODO(), nil, "database transaction timeout!")
				return errors.New("database transaction timeout")
			}
		}()
	}

	// If we are in a transaction, simply execute the passed function
	return todo()
}

func (s *serviceContextImpl) endTransaction() {
	s.inTransaction = false
}

type ServiceFactory struct {
	contextProducer svcContext.ServiceContextProducer
	config          *configuration.Configuration
}

// Option an option to configure the Service Factory
type Option func(f *ServiceFactory)

func NewServiceFactory(producer svcContext.ServiceContextProducer, config *configuration.Configuration, options ...Option) *ServiceFactory {
	f := &ServiceFactory{contextProducer: producer, config: config}

	log.Debug(context.TODO(), map[string]interface{}{}, "configuring a new service factory with %d options", len(options))
	// and options
	for _, opt := range options {
		opt(f)
	}
	return f
}

func (f *ServiceFactory) getContext() svcContext.ServiceContext {
	return f.contextProducer()
}
