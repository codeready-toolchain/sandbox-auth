package gormsupport

import "time"

// LifecycleHardDelete struct contains all the items from gorm.Model except the ID and DeletedAt field,
// hence we can embed the LifecycleHardDelete struct into Models that needs hard delete and alike.
type LifecycleHardDelete struct {
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Equal returns true if two LifecycleHardDelete objects are equal; otherwise false is returned.
func (lc LifecycleHardDelete) Equal(u Equaler) bool {
	other, ok := u.(LifecycleHardDelete)
	return ok && lc.CreatedAt.Equal(other.CreatedAt) && lc.UpdatedAt.Equal(other.UpdatedAt)
}
