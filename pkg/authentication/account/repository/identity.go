package repository

import (
	"context"
	"github.com/codeready-toolchain/sandbox-auth/gormsupport"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/repository/base"
	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

type Identity struct {
	gormsupport.Lifecycle
	IdentityID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:identity_id"`
	Username   string

	// Link to User
	UserID uuid.UUID `sql:"type:uuid" gorm:"column:user_id"`
	User   User      `gorm:"foreignkey:UserID;association_foreignkey:UserID"`
}

func (m Identity) TableName() string {
	return "identity"
}

type IdentityRepository interface {
	base.Exister
	Load(ctx context.Context, id uuid.UUID, funcs ...func(*gorm.DB) *gorm.DB) (*Identity, error)
	LoadWithUser(ctx context.Context, id uuid.UUID) (*Identity, error)
	LoadForUser(ctx context.Context, userID uuid.UUID) (*Identity, error)
	LoadForUsers(ctx context.Context, userIDs []uuid.UUID) ([]Identity, error)
	Create(ctx context.Context, identity *Identity) error
	Save(ctx context.Context, identity *Identity) error
	Delete(ctx context.Context, id uuid.UUID, funcs ...func(*gorm.DB) *gorm.DB) error
	List(ctx context.Context) ([]Identity, error)
	Query(ctx context.Context, funcs ...func(*gorm.DB) *gorm.DB) ([]Identity, error)
}
