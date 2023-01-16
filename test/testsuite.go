package test

import (
	"context"
	"fmt"
	"github.com/codeready-toolchain/sandbox-auth/gormapplication"
	"github.com/codeready-toolchain/sandbox-auth/migration"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application"
	"github.com/codeready-toolchain/sandbox-auth/pkg/configuration"
	"github.com/codeready-toolchain/sandbox-auth/pkg/log"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"time"
)

type UnitTestSuite struct {
	suite.Suite
}

func NewDBTestSuite() DBTestSuite {
	return DBTestSuite{}
}

type DBTestSuite struct {
	suite.Suite
	Configuration *configuration.Configuration
	DB            *gorm.DB
	DBUrl         string
	DBContainer   *postgresContainer
	Application   application.Application
	Ctx           context.Context
}

func (s *DBTestSuite) SetupSuite() {
	ctx := context.Background()

	config := configuration.NewConfiguration()

	pg, err := setupPostgres(ctx, config)
	if err != nil {
		s.T().Fatal(err)
	}

	s.DBContainer = pg

	dbHost, err := pg.Container.Host(ctx)
	if err != nil {
		log.Panic(ctx, map[string]interface{}{
			"err": err,
		}, "ERROR: Unable to retrieve DB host")
		s.T().Fatal(err)
	}

	connectString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		dbHost,
		pg.MappedPort.Port(),
		config.GetPostgresUser(),
		config.GetPostgresPassword(),
		config.GetPostgresDatabase(),
		config.GetPostgresSSLMode(),
		config.GetPostgresConnectionTimeout())

	s.DB, err = gorm.Open(postgres.Open(connectString), &gorm.Config{
		NowFunc: func() time.Time {
			return time.Now().Round(time.Microsecond)
		},
	})
	if err != nil {
		log.Panic(ctx, map[string]interface{}{
			"err":        err,
			"connection": connectString,
		}, "ERROR: Unable to open connection to database")
		s.T().Fatal(err)
	}

	db, err := s.DB.DB()
	if err != nil {
		log.Panic(ctx, map[string]interface{}{
			"err":        err,
			"connection": connectString,
		}, "ERROR: Unable to open connection to database")
		s.T().Fatal(err)
	}

	// Run the migration
	err = migration.Migrate(db, config.GetPostgresDatabase())
	if err != nil {
		log.Panic(context.TODO(), map[string]interface{}{
			"err": err,
		}, "failed migration")
	}

	s.Configuration = config
	s.Application = gormapplication.NewGormDB(s.DB, s.Configuration)
	s.Ctx = context.Background()
}

func (s *DBTestSuite) TearDownSuite() {
	ctx := context.Background()
	if err := s.DBContainer.Terminate(ctx); err != nil {
		s.T().Fatalf("failed to terminate container: %s", err)
	}
}

type postgresContainer struct {
	testcontainers.Container
	MappedPort nat.Port
}

func setupPostgres(ctx context.Context, config *configuration.Configuration) (*postgresContainer, error) {

	req := testcontainers.ContainerRequest{
		Name:         "sandbox-auth-postgres",
		Image:        "docker.io/postgres:14",
		ExposedPorts: []string{fmt.Sprintf("%d/tcp", config.GetPostgresPort())},
		//Networks:     []string{networkName},
		AutoRemove: true,
		SkipReaper: true,
		WaitingFor: wait.ForListeningPort(nat.Port(fmt.Sprintf("%d/tcp", config.GetPostgresPort()))),
		Env: map[string]string{
			"POSTGRES_DB":       config.GetPostgresDatabase(),
			"POSTGRES_PASSWORD": config.GetPostgresPassword(),
			"POSTGRES_USER":     config.GetPostgresUser(),
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

	mappedPort, err := container.MappedPort(ctx, "5432")
	if err != nil {
		return nil, err
	}

	return &postgresContainer{Container: container, MappedPort: mappedPort}, nil
}
