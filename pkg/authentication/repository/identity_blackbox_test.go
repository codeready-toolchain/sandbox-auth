package repository_test

import (
	"github.com/codeready-toolchain/sandbox-auth/pkg/authentication/repository"
	"github.com/codeready-toolchain/sandbox-auth/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type IdentityRepositoryTestSuite struct {
	test.DBTestSuite
}

func TestIdentityRepository(t *testing.T) {
	suite.Run(t, &IdentityRepositoryTestSuite{DBTestSuite: test.NewDBTestSuite()})
}

func (s *IdentityRepositoryTestSuite) TestRepositoryActions() {
	identity := &repository.Identity{
		Username: "john.smith",
	}

	require.NoError(s.T(), s.Application.IdentityRepository().Create(s.Ctx, identity))
	require.NotNil(s.T(), identity.IdentityID)
	require.Equal(s.T(), "john.smith", identity.Username)
	require.NotNil(s.T(), identity.CreatedAt)

	// Create some noise
	require.NoError(s.T(), s.Application.IdentityRepository().Create(s.Ctx, &repository.Identity{Username: "sarah.jones"}))
	require.NoError(s.T(), s.Application.IdentityRepository().Create(s.Ctx, &repository.Identity{Username: "m.thomas"}))

	// Load the original identity
	loaded, err := s.Application.IdentityRepository().Load(s.Ctx, identity.IdentityID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), "john.smith", loaded.Username)
	require.NotNil(s.T(), loaded.CreatedAt)
	require.Equal(s.T(), loaded.CreatedAt, loaded.UpdatedAt)

	// Change the username and call Save()
	loaded.Username = "john.j.smith"
	require.NoError(s.T(), s.Application.IdentityRepository().Save(s.Ctx, loaded))

	// Reload the original identity again, and confirm the Username has been correctly saved
	reloaded, err := s.Application.IdentityRepository().Load(s.Ctx, identity.IdentityID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), "john.j.smith", reloaded.Username)
	require.NotEqual(s.T(), reloaded.CreatedAt, reloaded.UpdatedAt)

	// Delete the original identity
	require.NoError(s.T(), s.Application.IdentityRepository().Delete(s.Ctx, reloaded.IdentityID))

	// Confirm it was deleted
	loaded, err = s.Application.IdentityRepository().Load(s.Ctx, reloaded.IdentityID)
	require.Nil(s.T(), loaded)

}
