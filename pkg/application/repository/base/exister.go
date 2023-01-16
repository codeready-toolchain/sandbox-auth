package base

import (
	"context"
	"fmt"
	"github.com/codeready-toolchain/sandbox-auth/pkg/errors"
	errs "github.com/pkg/errors"
	"gorm.io/gorm"
)

type Exister interface {
	// Exists returns nil if the object with the given ID exists;
	// otherwise an error is returned in case the given ID doesn't exists or any
	// other unknown issue occurred
	CheckExists(ctx context.Context, id string) error
}

// exists returns true if a soft or hard deletable item exists in the database table with a given ID
//nolint:all
func exists(db *gorm.DB, tableName, idColumnName, id string, softDeletable bool) (bool, error) {
	var exists bool
	var query string
	if softDeletable {
		query = fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				%[2]s=$1
				AND deleted_at IS NULL
		)`, tableName, idColumnName)
	} else {
		query = fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				%[2]s=$1
		)`, tableName, idColumnName)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return false, err
	}
	err = sqlDB.QueryRow(query, id).Scan(&exists)
	if err == nil && !exists {
		return exists, errors.NewNotFoundError(tableName, id)
	}
	if err != nil {
		return false, errors.NewInternalError(errs.Wrapf(err, "unable to verify if %s exists", tableName))
	}
	return exists, nil
}

// CheckExists does the same as Exists for a soft deletable item but only returns the error value; thereby
// being a handy convenience function.
//
//nolint:unused
func CheckExists(db *gorm.DB, tableName string, id string) error {
	_, err := exists(db, tableName, "id", id, true)
	return err
}

// CheckExistsWithCustomIDColumn does the same as CheckExists but allows to use custom ID column name
// instead of the default "id"
//
//nolint:unused
func CheckExistsWithCustomIDColumn(db *gorm.DB, tableName, idColumnName, id string) error {
	_, err := exists(db, tableName, idColumnName, id, true)
	return err
}

// CheckExists does the same as Exists for a hard deletable item but only returns the error value; thereby
// being a handy convenience function.
//
//nolint:unused
func CheckHardDeletableExists(db *gorm.DB, tableName string, id string) error {
	_, err := exists(db, tableName, "id", id, false)
	return err
}
