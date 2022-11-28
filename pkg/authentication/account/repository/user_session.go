package repository

import (
	"context"
	"github.com/gofrs/uuid"
	"time"
)

type UserSession struct {
	UserSessionID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:user_session_id"`

	UserID uuid.UUID `sql:"type:uuid"`
	User   User      `gorm:"foreignkey:UserID;association_foreignkey:UserID"`

	SessionCreated time.Time `gorm:"column:session_created"`

	LastActive time.Time `gorm:"column:last_active"`

	SessionTerminated *time.Time `gorm:"column:session_terminated"`
}

func (m UserSession) TableName() string {
	return "user_session"
}

type UserSessionRepository interface {
	Load(ctx context.Context, userSessionID uuid.UUID) (*UserSession, error)
	Create(ctx context.Context, u *UserSession) error
	Save(ctx context.Context, u *UserSession) error
	TouchLastActive(ctx context.Context, userSessionID uuid.UUID) error
	Search(ctx context.Context, userID uuid.UUID) ([]UserSession, error)
}
