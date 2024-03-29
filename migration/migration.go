package migration

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"embed"
	"text/template"

	"github.com/codeready-toolchain/sandbox-auth/pkg/log"
	errs "github.com/pkg/errors"
)

//go:embed sql-files/*
var sqlFiles embed.FS

// AdvisoryLockID is a random number that should be used within the application
// by anybody who wants to modify the "version" table.
const AdvisoryLockID = 42

// fn defines the type of function that can be part of a migration steps
type VersionFunction func(tx *sql.Tx) error

// steps defines a collection of all the functions that make up a version
type steps []VersionFunction

// Migrations defines all a collection of all the steps
type Migrations []steps

// Migrate executes the required migration of the database on startup.
// For each successful migration, an entry will be written into the "version"
// table, that states when a certain version was reached.
func Migrate(db *sql.DB, catalog string) error {

	var err error
	if db == nil {
		return errs.Errorf("Database handle is nil\n")
	}

	m := GetMigrations()

	var tx *sql.Tx
	for nextVersion := int64(0); nextVersion < int64(len(m)) && err == nil; nextVersion++ {

		tx, err = db.Begin()
		if err != nil {
			return errs.Errorf("Failed to start transaction: %s\n", err)
		}

		err = MigrateToNextVersion(tx, &nextVersion, m, catalog)

		if err != nil {
			oldErr := err
			log.Info(context.TODO(), map[string]interface{}{
				"next_version": nextVersion,
				"migrations":   m,
				"err":          err,
			}, "Rolling back transaction due to: %v", err)

			if err = tx.Rollback(); err != nil {
				log.Error(context.TODO(), map[string]interface{}{
					"next_version": nextVersion,
					"migrations":   m,
					"err":          err,
				}, "error while rolling back transaction")
				return errs.Errorf("Error while rolling back transaction: %s\n", err)
			}
			return oldErr
		}

		if err = tx.Commit(); err != nil {
			log.Error(context.TODO(), map[string]interface{}{
				"migrations": m,
				"err":        err,
			}, "error during transaction commit: %v", err)
			return errs.Errorf("Error during transaction commit: %s\n", err)
		}

	}

	if err != nil {
		log.Error(context.TODO(), map[string]interface{}{
			"migrations": m,
			"err":        err,
		}, "migration failed with error: %v", err)
		return errs.Errorf("Migration failed with error: %s\n", err)
	}

	return nil
}

// GetMigrations returns the migrations all the migrations we have.
// Add your own migration to the end of this function.
// IMPORTANT: ALWAYS APPEND AT THE END AND DON'T CHANGE THE ORDER OF MIGRATIONS!
func GetMigrations() Migrations {
	m := Migrations{}

	// Version 0
	m = append(m, steps{ExecuteSQLFile("000-bootstrap.sql")})

	// Version 1
	m = append(m, steps{ExecuteSQLFile("001-initial-schema.sql")})

	// Version 2
	//	m = append(m, steps{ExecuteSQLFile("002-initial-data.sql")})

	// Version N
	//
	// In order to add an upgrade, simply append an array of MigrationFunc to the
	// the end of the "migrations" slice. The version numbers are determined by
	// the index in the array. The following code in comments show how you can
	// do a migration in 3 steps. If one of the steps fails, the others are not
	// executed.
	// If something goes wrong during the migration, all you need to do is return
	// an error that is not nil.

	/*
		m = append(m, steps{
			func(db *sql.Tx) error {
				// Execute random go code
				return nil
			},
			ExecuteSQLFile("YOUR_OWN_FILE.sql"),
			func(db *sql.Tx) error {
				// Execute random go code
				return nil
			},
		})
	*/

	return m
}

// ExecuteSQLFile loads the given filename from the packaged SQL files and
// executes it on the given database. Golang text/template module is used
// to handle all the optional arguments passed to the sql files
func ExecuteSQLFile(filename string, args ...string) VersionFunction {
	return func(db *sql.Tx) error {
		data, err := sqlFiles.ReadFile("sql-files/" + filename)
		if err != nil {
			return errs.Wrapf(err, "failed to find filename: %s", filename)
		}

		if len(args) > 0 {
			tmpl, err := template.New("sql").Parse(string(data))
			if err != nil {
				return errs.Wrap(err, "failed to parse SQL template")
			}
			var sqlScript bytes.Buffer
			writer := bufio.NewWriter(&sqlScript)

			err = tmpl.Execute(writer, args)
			if err != nil {
				return errs.Wrap(err, "failed to execute SQL template")
			}
			// We need to flush the content of the writer
			writer.Flush()

			_, err = db.Exec(sqlScript.String())
			if err != nil {
				log.Error(context.Background(), map[string]interface{}{
					"err": err,
				}, "failed to execute this query: \n\n%s\n\n", sqlScript.String())
			}

		} else {
			_, err = db.Exec(string(data))
			if err != nil {
				log.Error(context.Background(), map[string]interface{}{
					"err": err,
				}, "failed to execute this query: \n\n%s\n\n", string(data))
			}
		}

		return errs.WithStack(err)
	}
}

// MigrateToNextVersion migrates the database to the nextVersion.
// If the database is already at nextVersion or higher, the nextVersion
// will be set to the actual next version.
func MigrateToNextVersion(tx *sql.Tx, nextVersion *int64, m Migrations, catalog string) error {
	// Obtain exclusive transaction level advisory that doesn't depend on any table.
	// Once obtained, the lock is held for the remainder of the current transaction.
	// (There is no UNLOCK TABLE command; locks are always released at transaction end.)
	if _, err := tx.Exec("SELECT pg_advisory_xact_lock($1)", AdvisoryLockID); err != nil {
		return errs.Errorf("Failed to acquire lock: %s\n", err)
	}

	// Determine current version and adjust the outmost loop
	// iterator variable "version"
	currentVersion, err := getCurrentVersion(tx, catalog)
	if err != nil {
		return errs.WithStack(err)
	}
	*nextVersion = currentVersion + 1
	if *nextVersion >= int64(len(m)) {
		// No further updates to apply (this is NOT an error)
		log.Info(context.TODO(), map[string]interface{}{
			"next_version":    *nextVersion,
			"current_version": currentVersion,
		}, "Current version %d. Nothing to update.", currentVersion)
		return nil
	}

	log.Info(context.TODO(), map[string]interface{}{
		"next_version":    *nextVersion,
		"current_version": currentVersion,
	}, "Attempt to update DB to version %v", *nextVersion)

	// Apply all the updates of the next version
	for j := range m[*nextVersion] {
		if err := m[*nextVersion][j](tx); err != nil {
			return errs.Errorf("Failed to execute migration of step %d of version %d: %s\n", j, *nextVersion, err)
		}
	}

	if _, err := tx.Exec("INSERT INTO version(version) VALUES($1)", *nextVersion); err != nil {
		return errs.Errorf("Failed to update DB to version %d: %s\n", *nextVersion, err)
	}

	log.Info(context.TODO(), map[string]interface{}{
		"next_version":    *nextVersion,
		"current_version": currentVersion,
	}, "Successfully updated DB to version %v", *nextVersion)

	return nil
}

// getCurrentVersion returns the highest version from the version
// table or -1 if that table does not exist.
//
// Returning -1 simplifies the logic of the migration process because
// the next version is always the current version + 1 which results
// in -1 + 1 = 0 which is exactly what we want as the first version.
func getCurrentVersion(db *sql.Tx, catalog string) (int64, error) {
	query := `SELECT EXISTS(
				SELECT 1 FROM information_schema.tables
				WHERE table_catalog=$1
				AND table_name='version')`
	row := db.QueryRow(query, catalog)

	var exists bool
	if err := row.Scan(&exists); err != nil {
		return -1, errs.Errorf("Failed to scan if table \"version\" exists: %s\n", err)
	}

	if !exists {
		// table doesn't exist
		return -1, nil
	}

	row = db.QueryRow("SELECT max(version) as current FROM version")

	var current int64 = -1
	if err := row.Scan(&current); err != nil {
		return -1, errs.Errorf("Failed to scan max version in table \"version\": %s\n", err)
	}

	return current, nil
}
