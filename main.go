package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"github.com/codeready-toolchain/sandbox-auth/gormapplication"
	"github.com/codeready-toolchain/sandbox-auth/pkg/application/transaction"
	"github.com/codeready-toolchain/sandbox-auth/pkg/configuration"
	"github.com/codeready-toolchain/sandbox-auth/pkg/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/url"
	"os"
	"os/signal"
	osUser "os/user"
	"runtime"
	"strings"
	"sync"
	"time"
)

func main() {
	// --------------------------------------------------------------------
	// Parse flags
	// --------------------------------------------------------------------
	var migrateDB bool
	flag.BoolVar(&migrateDB, "migrateDatabase", false, "Migrates the database to the newest version and exits.")
	var (
		printConfig = flag.Bool("printConfig", false, "Prints the config (including merged environment variables) and exits")
		hostF       = flag.String("host", "localhost", "Server host (valid values: localhost)")
		domainF     = flag.String("domain", "", "Host domain name (overrides host domain specified in service design)")
		httpPortF   = flag.String("http-port", "", "HTTP port (overrides host HTTP port specified in service design)")
		secureF     = flag.Bool("secure", false, "Use secure scheme (https or grpcs)")
		dbgF        = flag.Bool("debug", false, "Log request and response bodies")
	)
	flag.Parse()

	config, err := configuration.NewConfiguration()
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"err": err,
		}, "failed to load configuration")
	}

	if *printConfig {
		os.Exit(0)
	}

	printUserInfo()

	var db *gorm.DB
	var sqlDB *sql.DB

	for {
		db, err := gorm.Open(postgres.Open(config.GetPostgresConfigString()), &gorm.Config{
			NowFunc: func() time.Time {
				return time.Now().Round(time.Microsecond)
			},
		})
		if err != nil {
			log.Logger().Errorf("ERROR: Unable to open connection to database %v", err)
		}
		sqlDB, err = db.DB()
		if err != nil {
			sqlDB.Close()
			log.Logger().Errorf("ERROR: Unable to obtain underlying connection to database %v", err)
			log.Logger().Infof("Retrying to connect in %v...", config.GetPostgresConnectionRetrySleep())
			time.Sleep(config.GetPostgresConnectionRetrySleep())
		} else {
			defer sqlDB.Close()
			break
		}
	}

	if config.GetPostgresConnectionMaxIdle() > 0 {
		log.Logger().Infof("Configured connection pool max idle %v", config.GetPostgresConnectionMaxIdle())
		sqlDB.SetMaxIdleConns(config.GetPostgresConnectionMaxIdle())
	}
	if config.GetPostgresConnectionMaxOpen() > 0 {
		log.Logger().Infof("Configured connection pool max open %v", config.GetPostgresConnectionMaxOpen())
		sqlDB.SetMaxOpenConns(config.GetPostgresConnectionMaxOpen())
	}

	// Set the database transaction timeout
	transaction.SetDatabaseTransactionTimeout(config.GetPostgresTransactionTimeout())

	// TODO DB migration here

	appDB := gormapplication.NewGormDB(db, config)

	log.Logger().Infoln("Application initialized: ", appDB)
	log.Logger().Infoln("GOMAXPROCS:              ", runtime.GOMAXPROCS(-1))
	log.Logger().Infoln("NumCPU:                  ", runtime.NumCPU())

	// Create channel used by both the signal handler and server goroutines
	// to notify the main goroutine when to stop the server.
	errc := make(chan error)

	// Setup interrupt handler. This optional step configures the process so
	// that SIGINT and SIGTERM signals cause the services to stop gracefully.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		errc <- fmt.Errorf("%s", <-c)
	}()

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	// TODO init background workers here, e.g. token cleanup

	// Start the servers and send errors (if any) to the error channel.
	switch *hostF {
	case "localhost":
		{
			addr := "http://0.0.0.0:8000/api"
			u, err := url.Parse(addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid URL %#v: %s", addr, err)
				os.Exit(1)
			}
			if *secureF {
				u.Scheme = "https"
			}
			if *domainF != "" {
				u.Host = *domainF
			}
			if *httpPortF != "" {
				h := strings.Split(u.Host, ":")[0]
				u.Host = h + ":" + *httpPortF
			} else if u.Port() == "" {
				u.Host += ":80"
			}
			handleHTTPServer(ctx, u,
				&wg, errc, log.Logger(), *dbgF)
		}

	default:
		fmt.Fprintf(os.Stderr, "invalid host argument: %q (valid hosts: localhost)", *hostF)
	}

	// Wait for signal.
	log.Logger().Printf("exiting (%v)", <-errc)

	// Send cancellation signal to the goroutines.
	cancel()

	wg.Wait()
	log.Logger().Println("exited")
}

type Worker interface {
	Start(freq time.Duration)
	Stop()
}

func configFileFromFlags(flagName string, envVarName string) string {
	configSwitchIsSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == flagName {
			configSwitchIsSet = true
		}
	})
	if !configSwitchIsSet {
		if envConfigPath, ok := os.LookupEnv(envVarName); ok {
			return envConfigPath
		}
	}
	return ""
}

func printUserInfo() {
	u, err := osUser.Current()
	if err != nil {
		log.Warn(nil, map[string]interface{}{
			"err": err,
		}, "failed to get current user")
	} else {
		log.Info(nil, map[string]interface{}{
			"username": u.Username,
			"uuid":     u.Uid,
		}, "Running as user name '%s' with UID %s.", u.Username, u.Uid)
		g, err := osUser.LookupGroupId(u.Gid)
		if err != nil {
			log.Warn(nil, map[string]interface{}{
				"err": err,
			}, "failed to lookup group")
		} else {
			log.Info(nil, map[string]interface{}{
				"groupname": g.Name,
				"gid":       g.Gid,
			}, "Running as as group '%s' with GID %s.", g.Name, g.Gid)
		}
	}
}
