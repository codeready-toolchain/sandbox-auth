package gormsupport

import (
	"gorm.io/gorm"
	"time"
)

// The Lifecycle struct contains all the items from gorm.Model except the ID field,
// hence we can embed the Lifecycle struct into Models that needs soft delete and alike.
type Lifecycle struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

// Equal returns true if two Lifecycle objects are equal; otherwise false is returned.
func (lc Lifecycle) Equal(u Equaler) bool {
	other, ok := u.(Lifecycle)
	if !ok {
		return false
	}
	if !lc.CreatedAt.Equal(other.CreatedAt) {
		return false
	}
	if !lc.UpdatedAt.Equal(other.UpdatedAt) {
		return false
	}
	// DeletedAt can be nil so we need to do a special check here.
	if lc.DeletedAt.Valid && other.DeletedAt.Valid {
		return true
	}
	if lc.DeletedAt.Valid && !other.DeletedAt.Valid {
		return lc.DeletedAt.Time.Equal(other.DeletedAt.Time)
	}
	return false
}
