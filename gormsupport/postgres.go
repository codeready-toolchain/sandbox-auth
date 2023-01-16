package gormsupport

import (
	"github.com/lib/pq"
	"github.com/pkg/errors"
)

const (
	errCheckViolation      = "23514"
	errUniqueViolation     = "23505"
	errForeignKeyViolation = "23503"
)

// IsCheckViolation returns true if the error is a violation of the given check
func IsCheckViolation(err error, constraintName string) bool {
	if err == nil {
		return false
	}
	var pqError *pq.Error
	ok := errors.As(err, pqError)
	if !ok {
		return false
	}
	return pqError.Code == errCheckViolation && pqError.Constraint == constraintName
}

// IsUniqueViolation returns true if the error is a violation of the given unique index
func IsUniqueViolation(err error, indexName string) bool {
	if err == nil {
		return false
	}
	var pqError *pq.Error
	ok := errors.As(err, pqError)
	if !ok {
		return false
	}
	return pqError.Code == errUniqueViolation && pqError.Constraint == indexName
}

// IsForeignKeyViolation returns true if the error is a violation of the given foreign key index
func IsForeignKeyViolation(err error, indexName string) bool {
	if err == nil {
		return false
	}
	var pqError *pq.Error
	ok := errors.As(err, pqError)
	if !ok {
		return false
	}
	return pqError.Code == errForeignKeyViolation && pqError.Constraint == indexName
}
