package configuration

import (
	"fmt"
	"github.com/spf13/viper"
	"strings"
	"time"
)

const (

	// POSTGRES

	varPostgresHost                 = "postgres.host"
	varPostgresPort                 = "postgres.port"
	varPostgresUser                 = "postgres.user"
	varPostgresDatabase             = "postgres.database"
	varPostgresPassword             = "postgres.password"
	varPostgresSSLMode              = "postgres.sslmode"
	varPostgresConnectionTimeout    = "postgres.connection.timeout"
	varPostgresTransactionTimeout   = "postgres.transaction.timeout"
	varPostgresConnectionRetrySleep = "postgres.connection.retrysleep"
	varPostgresConnectionMaxIdle    = "postgres.connection.maxidle"
	varPostgresConnectionMaxOpen    = "postgres.connection.maxopen"

	defaultDBPassword = "mysecretpassword"
)

type Configuration struct {
	v *viper.Viper
}

func NewConfiguration() *Configuration {
	c := &Configuration{
		v: viper.New(),
	}

	c.v.SetEnvPrefix("AUTH")
	c.v.AutomaticEnv()
	c.v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	c.v.SetTypeByDefaultValue(true)
	c.setDefaults()

	return c
}

func (c *Configuration) setDefaults() {
	c.v.SetDefault(varPostgresHost, "localhost")
	c.v.SetDefault(varPostgresPort, 5432)
	c.v.SetDefault(varPostgresUser, "postgres")
	c.v.SetDefault(varPostgresDatabase, "postgres")
	c.v.SetDefault(varPostgresPassword, defaultDBPassword)
	c.v.SetDefault(varPostgresSSLMode, "disable")
	c.v.SetDefault(varPostgresConnectionTimeout, 5)
	c.v.SetDefault(varPostgresConnectionMaxIdle, -1)
	c.v.SetDefault(varPostgresConnectionMaxOpen, -1)
	c.v.SetDefault(varPostgresConnectionRetrySleep, time.Duration(time.Second))
	c.v.SetDefault(varPostgresTransactionTimeout, time.Duration(5*time.Minute))
}

func (c *Configuration) GetPostgresHost() string {
	return c.v.GetString(varPostgresHost)
}

func (c *Configuration) GetPostgresPort() int64 {
	return c.v.GetInt64(varPostgresPort)
}

func (c *Configuration) GetPostgresUser() string {
	return c.v.GetString(varPostgresUser)
}

func (c *Configuration) GetPostgresDatabase() string {
	return c.v.GetString(varPostgresDatabase)
}

func (c *Configuration) GetPostgresPassword() string {
	return c.v.GetString(varPostgresPassword)
}

func (c *Configuration) GetPostgresSSLMode() string {
	return c.v.GetString(varPostgresSSLMode)
}

func (c *Configuration) GetPostgresConnectionTimeout() int64 {
	return c.v.GetInt64(varPostgresConnectionTimeout)
}

func (c *Configuration) GetPostgresConnectionRetrySleep() time.Duration {
	return c.v.GetDuration(varPostgresConnectionRetrySleep)
}

func (c *Configuration) GetPostgresTransactionTimeout() time.Duration {
	return c.v.GetDuration(varPostgresTransactionTimeout)
}

func (c *Configuration) GetPostgresConnectionMaxIdle() int {
	return c.v.GetInt(varPostgresConnectionMaxIdle)
}

func (c *Configuration) GetPostgresConnectionMaxOpen() int {
	return c.v.GetInt(varPostgresConnectionMaxOpen)
}

func (c *Configuration) GetPostgresConfigString() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		c.GetPostgresHost(),
		c.GetPostgresPort(),
		c.GetPostgresUser(),
		c.GetPostgresPassword(),
		c.GetPostgresDatabase(),
		c.GetPostgresSSLMode(),
		c.GetPostgresConnectionTimeout(),
	)
}
