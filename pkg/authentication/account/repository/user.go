package repository

import (
	"github.com/codeready-toolchain/sandbox-auth/gormsupport"
	"github.com/gofrs/uuid"
	"gorm.io/gorm"
	"time"
)

type User struct {
	gormsupport.Lifecycle

	UserID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:user_id"`

	Email    string `sql:"unique_index"`
	FullName string
	Enabled  bool `gorm:"column:enabled"`

	LastActive *time.Time

	PrimaryIdentity *Identity `gorm:"foreignkey:UserID;references:UserID"`
}

func (m User) TableName() string {
	return "app_user"
}

type GormUserRepository struct {
	db *gorm.DB
}
