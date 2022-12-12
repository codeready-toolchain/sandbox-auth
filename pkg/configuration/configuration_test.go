package configuration_test

import (
	"github.com/codeready-toolchain/sandbox-auth/pkg/configuration"
	"github.com/codeready-toolchain/sandbox-auth/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"os"
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
	require.Equal(s.T(), "postgres", cfg.GetPostgresUser())
	require.Equal(s.T(), "postgres", cfg.GetPostgresDatabase())
	require.Equal(s.T(), "mysecretpassword", cfg.GetPostgresPassword())
	require.Equal(s.T(), "disable", cfg.GetPostgresSSLMode())
	require.Equal(s.T(), int64(5), cfg.GetPostgresConnectionTimeout())
	require.Equal(s.T(), -1, cfg.GetPostgresConnectionMaxIdle())
	require.Equal(s.T(), -1, cfg.GetPostgresConnectionMaxOpen())
	require.Equal(s.T(), "host=localhost port=5433 user=postgres password=mysecretpassword dbname=postgres sslmode=disable connect_timeout=5", cfg.GetPostgresConfigString())
}

func (s *TestConfigurationSuite) TestConfiguration() {
	// Cleanup the environment when done
	defer func() {
		os.Unsetenv("AUTH_POSTGRES_HOST")
		os.Unsetenv("AUTH_POSTGRES_PORT")
		os.Unsetenv("AUTH_POSTGRES_USER")
		os.Unsetenv("AUTH_POSTGRES_DATABASE")
		os.Unsetenv("AUTH_POSTGRES_PASSWORD")
		os.Unsetenv("AUTH_POSTGRES_SSLMODE")
		os.Unsetenv("AUTH_POSTGRES_CONNECTION_TIMEOUT")
		os.Unsetenv("AUTH_POSTGRES_CONNECTION_MAXIDLE")
		os.Unsetenv("AUTH_POSTGRES_CONNECTION_MAXOPEN")
	}()

	// Set some environment variables to be loaded by the configuration
	require.NoError(s.T(), os.Setenv("AUTH_POSTGRES_HOST", "postgres.host"))
	require.NoError(s.T(), os.Setenv("AUTH_POSTGRES_PORT", "1234"))
	require.NoError(s.T(), os.Setenv("AUTH_POSTGRES_USER", "pguser"))
	require.NoError(s.T(), os.Setenv("AUTH_POSTGRES_DATABASE", "sandbox-auth"))
	require.NoError(s.T(), os.Setenv("AUTH_POSTGRES_PASSWORD", "mydifferentsecretpassword"))
	require.NoError(s.T(), os.Setenv("AUTH_POSTGRES_SSLMODE", "enable"))
	require.NoError(s.T(), os.Setenv("AUTH_POSTGRES_CONNECTION_TIMEOUT", "10"))
	require.NoError(s.T(), os.Setenv("AUTH_POSTGRES_CONNECTION_MAXIDLE", "65"))
	require.NoError(s.T(), os.Setenv("AUTH_POSTGRES_CONNECTION_MAXOPEN", "20"))

	// Create the configuration object
	cfg, err := configuration.NewConfiguration()
	require.NoError(s.T(), err)

	// Confirm the configuration parameters are set as expected
	require.Equal(s.T(), "postgres.host", cfg.GetPostgresHost())
	require.Equal(s.T(), int64(1234), cfg.GetPostgresPort())
	require.Equal(s.T(), "pguser", cfg.GetPostgresUser())
	require.Equal(s.T(), "sandbox-auth", cfg.GetPostgresDatabase())
	require.Equal(s.T(), "mydifferentsecretpassword", cfg.GetPostgresPassword())
	require.Equal(s.T(), "enable", cfg.GetPostgresSSLMode())
	require.Equal(s.T(), int64(10), cfg.GetPostgresConnectionTimeout())
	require.Equal(s.T(), 65, cfg.GetPostgresConnectionMaxIdle())
	require.Equal(s.T(), 20, cfg.GetPostgresConnectionMaxOpen())
}
