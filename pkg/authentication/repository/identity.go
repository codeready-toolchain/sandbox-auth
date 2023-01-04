package repository

import (
	"context"
	"github.com/codeready-toolchain/sandbox-auth/gormsupport"
	"github.com/codeready-toolchain/sandbox-auth/pkg/errors"
	"github.com/codeready-toolchain/sandbox-auth/pkg/log"
	"github.com/gofrs/uuid"
	errs "github.com/pkg/errors"
	"gorm.io/gorm"
)

const (
	TableName = "identity"
)

type Identity struct {
	gormsupport.Lifecycle

	IdentityID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:identity_id"`
	Username   string
}

type IdentityRepository interface {
	Create(ctx context.Context, identity *Identity) error
	Load(ctx context.Context, id uuid.UUID) (*Identity, error)
	Save(ctx context.Context, identity *Identity) error
	Delete(ctx context.Context, id uuid.UUID) error
}

func NewIdentityRepository(db *gorm.DB) *GormIdentityRepository {
	return &GormIdentityRepository{db: db}
}

type GormIdentityRepository struct {
	db *gorm.DB
}

func (r *GormIdentityRepository) Create(ctx context.Context, model *Identity) error {
	if model.IdentityID == uuid.Nil {
		var err error
		model.IdentityID, err = uuid.NewV4()
		if err != nil {
			return err
		}
	}
	err := r.db.WithContext(ctx).Create(model).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_id": model.IdentityID,
			"err":         err,
		}, "unable to create the identity")
		return errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"identity_id": model.IdentityID,
	}, "Identity created!")
	return nil
}

func (r *GormIdentityRepository) Load(ctx context.Context, identityID uuid.UUID) (*Identity, error) {
	var native Identity
	err := r.db.WithContext(ctx).Table(TableName).Where("identity_id = ?", identityID).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errs.WithStack(errors.NewNotFoundError("identity", identityID.String()))
	}

	return &native, errs.WithStack(err)
}

func (r *GormIdentityRepository) Save(ctx context.Context, model *Identity) error {
	err := r.db.WithContext(ctx).Save(model).Error

	log.Debug(ctx, map[string]interface{}{
		"identity_id": model.IdentityID,
	}, "Identity saved!")

	return errs.WithStack(err)
}

func (r *GormIdentityRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Delete(&Identity{}, id)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_id": id,
			"err":         result.Error,
		}, "unable to delete the identity")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("identity", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"identity_id": id,
	}, "Identity deleted!")

	return nil
}
