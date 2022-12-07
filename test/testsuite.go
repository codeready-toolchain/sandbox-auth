package test

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"testing"
)

type DBTestSuite struct {
	suite.Suite
	DBUrl      string
	DBInstance *postgresContainer
}

func (s *DBTestSuite) SetupSuite() {
	ctx := context.Background()

	pg, err := setupPostgres(ctx, s.T())
	if err != nil {
		s.T().Fatal(err)
	}

	s.DBInstance = pg
}

func (s *DBTestSuite) TearDownSuite() {
	ctx := context.Background()
	if err := s.DBInstance.Terminate(ctx); err != nil {
		s.T().Fatalf("failed to terminate container: %s", err)
	}
}

type postgresContainer struct {
	testcontainers.Container
	URI string
}

func setupPostgres(ctx context.Context, t *testing.T) (*postgresContainer, error) {

	req := testcontainers.ContainerRequest{
		Name:         "sandbox-auth-postgres",
		Image:        "postgres:14",
		ExposedPorts: []string{"5432/tcp"},
		//Networks:     []string{networkName},
		AutoRemove: true,
		SkipReaper: true,
		WaitingFor: wait.ForListeningPort("5432/tcp"),
		Env: map[string]string{
			"POSTGRES_DB":       "postgres",
			"POSTGRES_PASSWORD": "postgres",
			"POSTGRES_USER":     "postgres",
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ProviderType:     testcontainers.ProviderPodman,
		ContainerRequest: req,
		Started:          true,
		Reuse:            true,
	})
	if err != nil {
		return nil, err
	}

	ip, err := container.Host(ctx)
	if err != nil {
		return nil, err
	}

	mappedPort, err := container.MappedPort(ctx, "5432")
	if err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("http://%s:%s", ip, mappedPort.Port())

	return &postgresContainer{Container: container, URI: uri}, nil
}
