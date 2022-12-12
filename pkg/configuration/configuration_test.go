package configuration_test

import (
	"github.com/codeready-toolchain/sandbox-auth/pkg/configuration"
	"github.com/codeready-toolchain/sandbox-auth/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type TestConfigurationSuite struct {
	test.UnitTestSuite
}

func TestRunConfigurationSuite(t *testing.T) {
	suite.Run(t, &TestConfigurationSuite{test.UnitTestSuite{}})
}

func (s *TestConfigurationSuite) TestDefaults() {
	cfg, err := configuration.NewConfiguration()
	require.NoError(s.T(), err)

	require.Equal(s.T(), "localhost", cfg.GetPostgresHost())
	require.Equal(s.T(), int64(5433), cfg.GetPostgresPort())
}
