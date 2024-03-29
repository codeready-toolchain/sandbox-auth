package gormapplication

import (
	"fmt"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/service/factory"
	authrepo "github.com/codeready-toolchain/sandbox-auth/pkg/authentication/repository"
	"github.com/codeready-toolchain/sandbox-auth/pkg/configuration"
	"strconv"

	servicecontext "github.com/codeready-toolchain/sandbox-auth/pkg/application/service/context"
	//"github.com/codeready-toolchain/sandbox-auth/pkg/application/service/factory"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/transaction"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

// A TXIsoLevel specifies the characteristics of the transaction
// See https://www.postgresql.org/docs/9.3/static/sql-set-transaction.html
type TXIsoLevel int8

const (
	// TXIsoLevelDefault doesn't specify any transaction isolation level, instead the connection
	// based setting will be used.
	TXIsoLevelDefault TXIsoLevel = iota

	// TXIsoLevelReadCommitted means "A statement can only see rows committed before it began. This is the default."
	TXIsoLevelReadCommitted

	// TXIsoLevelRepeatableRead means "All statements of the current transaction can only see rows committed before the
	// first query or data-modification statement was executed in this transaction."
	TXIsoLevelRepeatableRead

	// TXIsoLevelSerializable means "All statements of the current transaction can only see rows committed
	// before the first query or data-modification statement was executed in this transaction.
	// If a pattern of reads and writes among concurrent serializable transactions would create a
	// situation which could not have occurred for any serial (one-at-a-time) execution of those
	// transactions, one of them will be rolled back with a serialization_failure error."
	TXIsoLevelSerializable
)

func NewGormDB(db *gorm.DB, config *configuration.Configuration, options ...factory.Option) *GormDB {
	g := new(GormDB)
	g.db = db.Set("gorm:save_associations", false)
	g.txIsoLevel = ""
	g.serviceFactory = factory.NewServiceFactory(func() servicecontext.ServiceContext {
		return factory.NewServiceContext(g, g, config, options...)
	}, config, options...)
	return g
}

// GormBase is a base struct for gorm implementations of db & transaction
type GormBase struct {
	db *gorm.DB
}

// GormTransaction implements the Transaction interface methods for committing or rolling back a transaction
type GormTransaction struct {
	GormBase
}

// GormDB implements the Manager interface methods for initiating a new transaction
type GormDB struct {
	GormBase
	txIsoLevel     string
	serviceFactory *factory.ServiceFactory
}

func (g *GormBase) newSession() *gorm.DB {
	return g.db.Session(&gorm.Session{})
}

//----------------------------------------------------------------------------------------------------------------------
//
// Repositories
//
//----------------------------------------------------------------------------------------------------------------------

func (g *GormBase) IdentityRepository() authrepo.IdentityRepository {
	return authrepo.NewIdentityRepository(g.newSession())
}

//----------------------------------------------------------------------------------------------------------------------
//
// Services
//
//----------------------------------------------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------------------------------------
//
// Misc
//
//----------------------------------------------------------------------------------------------------------------------

func (g *GormBase) DB() *gorm.DB {
	return g.db
}

// SetTransactionIsolationLevel sets the isolation level for
// See also https://www.postgresql.org/docs/9.3/static/sql-set-transaction.html
func (g *GormDB) SetTransactionIsolationLevel(level TXIsoLevel) error {
	switch level {
	case TXIsoLevelReadCommitted:
		g.txIsoLevel = "READ COMMITTED"
	case TXIsoLevelRepeatableRead:
		g.txIsoLevel = "REPEATABLE READ"
	case TXIsoLevelSerializable:
		g.txIsoLevel = "SERIALIZABLE"
	case TXIsoLevelDefault:
		g.txIsoLevel = ""
	default:
		return fmt.Errorf("Unknown transaction isolation level: " + strconv.FormatInt(int64(level), 10))
	}
	return nil
}

// BeginTransaction initiates a new transaction
func (g *GormDB) BeginTransaction() (transaction.Transaction, error) {
	tx := g.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	if len(g.txIsoLevel) != 0 {
		tx := tx.Exec(fmt.Sprintf("set transaction isolation level %s", g.txIsoLevel))
		if tx.Error != nil {
			return nil, tx.Error
		}
		return &GormTransaction{GormBase{tx}}, nil
	}
	return &GormTransaction{GormBase{tx}}, nil
}

// Commit commits the current transaction
func (g *GormTransaction) Commit() error {
	err := g.db.Commit().Error
	g.db = nil
	return errors.WithStack(err)
}

// Rollback rolls back current transaction
func (g *GormTransaction) Rollback() error {
	err := g.db.Rollback().Error
	g.db = nil
	return errors.WithStack(err)
}
