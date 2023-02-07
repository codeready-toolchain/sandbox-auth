package transaction

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"time"

	"github.com/codeready-toolchain/sandbox-auth/pkg/application/repository"
	"github.com/codeready-toolchain/sandbox-auth/pkg/log"
)

var databaseTransactionTimeout = 5 * time.Minute

func SetDatabaseTransactionTimeout(t time.Duration) {
	databaseTransactionTimeout = t
}

func DatabaseTransactionTimeout() time.Duration {
	return databaseTransactionTimeout
}

// TransactionalResources provides a reference to transactional resources available during a transaction
type TransactionalResources interface {
	repository.Repositories
}

// Transaction represents an existing transaction.  It provides access to transactional resources, plus methods to commit or roll back the transaction
type Transaction interface {
	TransactionalResources
	Commit() error
	Rollback() error
}

// Manager manages the lifecycle of a database transaction. The transactional resources (such as repositories)
// created for the transaction object make changes inside the transaction
type Manager interface {
	BeginTransaction() (Transaction, error)
}

// Transactional executes the given function in a transaction. If todo returns an error, the transaction is rolled back
func Transactional(tm Manager, todo func(f TransactionalResources) error) error {
	var tx Transaction
	var err error
	if tx, err = tm.BeginTransaction(); err != nil {
		log.Error(context.TODO(), map[string]interface{}{
			"err": err,
		}, "database BeginTransaction failed!")

		return errors.WithStack(err)
	}

	return func() error {
		errorChan := make(chan error, 1)
		txTimeout := time.After(databaseTransactionTimeout)

		go func(_ TransactionalResources) {
			defer func() {
				if err := recover(); err != nil {
					errorChan <- fmt.Errorf("Unknown error: %v", err)
				}
			}()
			errorChan <- todo(tx)
		}(tx)

		select {
		case err := <-errorChan:
			if err != nil {
				log.Debug(context.TODO(), nil, "Rolling back the transaction...")
				rbErr := tx.Rollback()
				if rbErr != nil {
					log.Error(context.TODO(), map[string]interface{}{
						"err": err,
					}, "failed to rollback transaction")
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
				}, "failed to commit transaction")
				return err
			}
			log.Debug(context.TODO(), nil, "Commit the transaction!")
			return nil
		case <-txTimeout:
			log.Debug(context.TODO(), nil, "Rolling back the transaction...")
			err = tx.Rollback()
			if err != nil {
				log.Error(context.TODO(), nil, "error rolling back transaction")
			}
			log.Error(context.TODO(), nil, "database transaction timeout!")
			return errors.New("database transaction timeout")
		}
	}()
}
