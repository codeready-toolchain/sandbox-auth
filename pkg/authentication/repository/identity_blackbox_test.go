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

func (s *IdentityRepositoryTestSuite) TestCreate() {
	identity := &repository.Identity{
		Username: "john.smith",
	}

	require.NoError(s.T(), s.Application.IdentityRepository().Create(s.Ctx, identity))
	require.NotNil(s.T(), identity.IdentityID)
	require.Equal(s.T(), "john.smith", identity.Username)
}
