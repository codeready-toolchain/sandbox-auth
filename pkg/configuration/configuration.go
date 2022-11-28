package configuration

import (
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// Constants for viper variable names. Will be used to set
	// default values as well as to get each value

	//------------------------------------------------------------------------------------------------------------------
	//
	// General
	//
	//------------------------------------------------------------------------------------------------------------------

	varBaseSiteURL     = "base.site.url"
	defaultBaseSiteURL = "http://localhost:3000"

	varHTTPAddress                         = "http.address"
	varDeveloperModeEnabled                = "developer.mode.enabled"
	varCleanTestDataEnabled                = "clean.test.data"
	varCleanTestDataErrorReportingRequired = "error.reporting.required"
	varDBLogsEnabled                       = "enable.db.logs"
	varNotApprovedRedirect                 = "notapproved.redirect"
	varHeaderMaxLength                     = "header.maxlength"
	defaultConfigFile                      = "config.yaml"
	varValidRedirectURLs                   = "redirect.valid"
	varLogLevel                            = "log.level"
	varLogJSON                             = "log.json"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Postgres
	//
	//------------------------------------------------------------------------------------------------------------------

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

	//------------------------------------------------------------------------------------------------------------------
	//
	// Authentication Provider
	//
	//------------------------------------------------------------------------------------------------------------------

	varOAuthProviderType             = "oauth.provider.type"
	varOAuthProviderClientID         = "oauth.provider.client.id"
	varOAuthProviderClientSecret     = "oauth.provider.client.secret"
	varOAuthProviderEndpointAuth     = "oauth.provider.endpoint.auth"
	varOAuthProviderEndpointUserInfo = "oauth.provider.endpoint.userinfo"
	varOAuthProviderEndpointToken    = "oauth.provider.endpoint.token"
	varOAuthProviderEndpointLogout   = "oauth.provider.endpoint.logout"
	varOAuthProviderScopes           = "oauth.provider.scopes"

	//------------------------------------------------------------------------------------------------------------------
	//
	// User Keys
	//
	//------------------------------------------------------------------------------------------------------------------

	// Private keys for signing Access and Refresh tokens
	varUserAccountPrivateKey   = "useraccount.privatekey"
	varUserAccountPrivateKeyID = "useraccount.privatekeyid"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Token configuration
	//
	//------------------------------------------------------------------------------------------------------------------

	varAccessTokenExpiresIn  = "useraccount.token.access.expiresin"  // In seconds
	varRefreshTokenExpiresIn = "useraccount.token.refresh.expiresin" // In seconds

	//------------------------------------------------------------------------------------------------------------------
	//
	// Cache control
	//
	//------------------------------------------------------------------------------------------------------------------

	varCacheControlUsers         = "cachecontrol.users"
	varCacheControlCollaborators = "cachecontrol.collaborators"
	varCacheControlUser          = "cachecontrol.user"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Privilege Cache
	//
	//------------------------------------------------------------------------------------------------------------------

	varPrivilegeCacheExpirySeconds = "privilege.cache.expiry.seconds"
	varRPTTokenMaxPermissions      = "rpt.token.max.permissions"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Other
	//
	//------------------------------------------------------------------------------------------------------------------

	// Public Client ID for logging into Auth service via OAuth2
	varPublicOAuthClientID = "public.oauth.client.id"

	// Token cleanup
	varExpiredTokenRetentionHours = "expired.token.retention.hours"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Settings
	//
	//------------------------------------------------------------------------------------------------------------------

	// varInstanceDescriptor Allows an instance descriptor to be set, which will be displayed at the top of the application window
	varInstanceDescriptor = "instance.descriptor"

	varRemoteIPHeader     = "remote.ip.header"
	defaultRemoteIPHeader = "X-Forwarded-For"
)

// ConfigurationData encapsulates the Viper configuration object which stores the configuration data in-memory.
type ConfigurationData struct {
	// Main Configuration
	v *viper.Viper

	defaultConfigurationError error

	mux sync.RWMutex
}

// String returns the current configuration as a string
func (c *ConfigurationData) String() string {
	allSettings := c.v.AllSettings()
	y, err := yaml.Marshal(&allSettings)
	if err != nil {
		log.WithFields(map[string]interface{}{
			"settings": allSettings,
			"err":      err,
		}).Panicln("Failed to marshall config to string")
	}
	return fmt.Sprintf("%s\n", y)
}

// NewConfigurationData creates a configuration reader object using configurable configuration file paths
func NewConfigurationData(mainConfigFile string) (*ConfigurationData, error) {
	c := &ConfigurationData{
		v: viper.New(),
	}

	// Set up the main configuration
	c.v.SetEnvPrefix("SYNOPTIC")
	c.v.AutomaticEnv()
	c.v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	c.v.SetTypeByDefaultValue(true)
	c.setConfigDefaults()

	if mainConfigFile != "" {
		c.v.SetConfigType("yaml")
		c.v.SetConfigFile(mainConfigFile)
		err := c.v.ReadInConfig() // Find and read the config file
		if err != nil {           // Handle errors reading the config file
			return nil, errors.Errorf("Fatal error config file: %s \n", err)
		}
	}

	// Check sensitive default configuration
	if c.IsPostgresDeveloperModeEnabled() {
		c.appendDefaultConfigErrorMessage("developer Mode is enabled")
	}
	key, kid := c.GetUserAccountPrivateKey()
	if string(key) == DefaultUserAccountPrivateKey {
		c.appendDefaultConfigErrorMessage("default user account private key is used")
	}
	if kid == defaultUserAccountPrivateKeyID {
		c.appendDefaultConfigErrorMessage("default user account private key ID is used")
	}
	if c.GetPostgresPassword() == defaultDBPassword {
		c.appendDefaultConfigErrorMessage("default DB password is used")
	}
	if c.GetOAuthProviderClientSecret() == defaultOAuthProviderClientSecret {
		c.appendDefaultConfigErrorMessage("default auth provider client secret is used")
	}
	if c.GetValidRedirectURLs() == ".*" {
		c.appendDefaultConfigErrorMessage("no restrictions for valid redirect URLs")
	}
	if c.GetAccessTokenExpiresIn() < 3*60 {
		c.appendDefaultConfigErrorMessage("too short lifespan of access tokens")
	}
	if c.GetRefreshTokenExpiresIn() < 3*60 {
		c.appendDefaultConfigErrorMessage("too short lifespan of refresh tokens")
	}
	if c.defaultConfigurationError != nil {
		log.WithFields(map[string]interface{}{
			"default_configuration_error": c.defaultConfigurationError.Error(),
		}).Warningln("Default config is used! This is OK in Dev Mode.")
	}

	return c, nil
}

func (c *ConfigurationData) validateURL(serviceURL, serviceName string) {
	if serviceURL == "" {
		c.appendDefaultConfigErrorMessage(fmt.Sprintf("%s url is empty", serviceName))
	} else {
		_, err := url.Parse(serviceURL)
		if err != nil {
			c.appendDefaultConfigErrorMessage(fmt.Sprintf("invalid %s url: %s", serviceName, err.Error()))
		}
	}
}

func (c *ConfigurationData) appendDefaultConfigErrorMessage(message string) {
	if c.defaultConfigurationError == nil {
		c.defaultConfigurationError = errors.New(message)
	} else {
		c.defaultConfigurationError = errors.Errorf("%s; %s", c.defaultConfigurationError.Error(), message)
	}
}

func pathExists(pathToCheck string) (string, error) {
	_, err := os.Stat(pathToCheck)
	if err == nil {
		return pathToCheck, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return "", nil
}

func getMainConfigFile() string {
	// This was either passed as a env var or set inside main.go from --config
	envConfigPath, _ := os.LookupEnv("SYNOPTIC_CONFIG_FILE_PATH")
	return envConfigPath
}

// DefaultConfigurationError returns an error if the default values is used
// for sensitive configuration like service account secrets or private keys.
// Error contains all the details.
// Returns nil if the default configuration is not used.
func (c *ConfigurationData) DefaultConfigurationError() error {
	// Lock for reading because config file watcher can update config errors
	c.mux.RLock()
	defer c.mux.RUnlock()

	return c.defaultConfigurationError
}

// GetDefaultConfigurationFile returns the default configuration file.
func (c *ConfigurationData) GetDefaultConfigurationFile() string {
	return defaultConfigFile
}

// GetConfigurationData is a wrapper over NewConfigurationData which reads configuration file path
// from the environment variable.
func GetConfigurationData() (*ConfigurationData, error) {
	return NewConfigurationData(getMainConfigFile())
}

func (c *ConfigurationData) setConfigDefaults() {

	//------------------------------------------------------------------------------------------------------------------
	//
	// Postgres
	//
	//------------------------------------------------------------------------------------------------------------------

	// We already call this in NewConfigurationData() - do we need it again??
	c.v.SetTypeByDefaultValue(true)

	c.v.SetDefault(varPostgresHost, "localhost")
	c.v.SetDefault(varPostgresPort, 5477)
	c.v.SetDefault(varPostgresUser, "postgres")
	c.v.SetDefault(varPostgresDatabase, "postgres")
	c.v.SetDefault(varPostgresPassword, defaultDBPassword)
	c.v.SetDefault(varPostgresSSLMode, "disable")
	c.v.SetDefault(varPostgresConnectionTimeout, 5)
	c.v.SetDefault(varPostgresConnectionMaxIdle, -1)
	c.v.SetDefault(varPostgresConnectionMaxOpen, -1)

	// Number of seconds to wait before trying to connect again
	c.v.SetDefault(varPostgresConnectionRetrySleep, time.Duration(time.Second))

	// Timeout of a transaction in minutes
	c.v.SetDefault(varPostgresTransactionTimeout, time.Duration(5*time.Minute))

	//------------------------------------------------------------------------------------------------------------------
	//
	// Authentication Provider Defaults
	//
	//------------------------------------------------------------------------------------------------------------------

	c.v.SetDefault(varOAuthProviderType, defaultOAuthProviderType)
	c.v.SetDefault(varOAuthProviderClientID, defaultOAuthProviderClientID)
	c.v.SetDefault(varOAuthProviderClientSecret, defaultOAuthProviderClientSecret)
	c.v.SetDefault(varOAuthProviderEndpointAuth, defaultOAuthProviderEndpointAuth)
	c.v.SetDefault(varOAuthProviderEndpointToken, defaultOAuthProviderEndpointToken)
	c.v.SetDefault(varOAuthProviderEndpointUserInfo, defaultOAuthProviderEndpointUserInfo)
	c.v.SetDefault(varOAuthProviderEndpointLogout, defaultOAuthProviderEndpointLogout)
	c.v.SetDefault(varOAuthProviderScopes, defaultOAuthProviderScopes)

	//------------------------------------------------------------------------------------------------------------------
	//
	// Http
	//
	//------------------------------------------------------------------------------------------------------------------

	c.v.SetDefault(varHTTPAddress, "0.0.0.0:8089")
	c.v.SetDefault(varHeaderMaxLength, defaultHeaderMaxLength)

	//------------------------------------------------------------------------------------------------------------------
	//
	// Misc
	//
	//------------------------------------------------------------------------------------------------------------------

	// Enable development related features, e.g. token generation endpoint
	c.v.SetDefault(varDeveloperModeEnabled, false)

	// By default, test data should be cleaned from DB, unless explicitely said otherwise.
	c.v.SetDefault(varCleanTestDataEnabled, true)
	// By default, error should be reported while cleaning test data from DB.
	c.v.SetDefault(varCleanTestDataErrorReportingRequired, true)
	// By default, DB logs are not output in the console
	c.v.SetDefault(varDBLogsEnabled, false)

	c.v.SetDefault(varLogLevel, defaultLogLevel)

	// By default, test data should be cleaned from DB, unless explicitely said otherwise.
	c.v.SetDefault(varCleanTestDataEnabled, true)
	// By default, DB logs are not output in the console
	c.v.SetDefault(varDBLogsEnabled, false)

	// Auth-related defaults
	c.v.SetDefault(varUserAccountPrivateKey, DefaultUserAccountPrivateKey)
	c.v.SetDefault(varUserAccountPrivateKeyID, defaultUserAccountPrivateKeyID)
	var in15Minutes int16
	in15Minutes = 15 * 60
	var in30Days int64
	in30Days = 30 * 24 * 60 * 60
	c.v.SetDefault(varAccessTokenExpiresIn, in15Minutes)
	c.v.SetDefault(varRefreshTokenExpiresIn, in30Days)
	c.v.SetDefault(varPublicOAuthClientID, defaultPublicOAuthClientID)

	// HTTP Cache-Control/max-age default
	c.v.SetDefault(varCacheControlUsers, "max-age=2")
	c.v.SetDefault(varCacheControlCollaborators, "max-age=2")
	// data returned from '/api/user' must not be cached by intermediate proxies,
	// but can only be kept in the client's local cache.
	c.v.SetDefault(varCacheControlUser, "private,max-age=10")

	// Expired token retention time, after which tokens will be cleaned up
	c.v.SetDefault(varExpiredTokenRetentionHours, defaultExpiredTokenRetentionHours)

	c.v.SetDefault(varRemoteIPHeader, defaultRemoteIPHeader)
}

// GetPostgresHost returns the postgres host as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresHost() string {
	return c.v.GetString(varPostgresHost)
}

// GetPostgresPort returns the postgres port as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresPort() int64 {
	return c.v.GetInt64(varPostgresPort)
}

// GetPostgresUser returns the postgres user as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresUser() string {
	return c.v.GetString(varPostgresUser)
}

// GetPostgresDatabase returns the postgres database as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresDatabase() string {
	return c.v.GetString(varPostgresDatabase)
}

// GetPostgresPassword returns the postgres password as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresPassword() string {
	return c.v.GetString(varPostgresPassword)
}

// GetPostgresSSLMode returns the postgres sslmode as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresSSLMode() string {
	return c.v.GetString(varPostgresSSLMode)
}

// GetPostgresConnectionTimeout returns the postgres connection timeout as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresConnectionTimeout() int64 {
	return c.v.GetInt64(varPostgresConnectionTimeout)
}

// GetPostgresConnectionRetrySleep returns the number of seconds (as set via default, config file, or environment variable)
// to wait before trying to connect again
func (c *ConfigurationData) GetPostgresConnectionRetrySleep() time.Duration {
	return c.v.GetDuration(varPostgresConnectionRetrySleep)
}

// GetPostgresTransactionTimeout returns the number of minutes to timeout a transaction
func (c *ConfigurationData) GetPostgresTransactionTimeout() time.Duration {
	return c.v.GetDuration(varPostgresTransactionTimeout)
}

// GetPostgresConnectionMaxIdle returns the number of connections that should be keept alive in the database connection pool at
// any given time. -1 represents no restrictions/default behavior
func (c *ConfigurationData) GetPostgresConnectionMaxIdle() int {
	return c.v.GetInt(varPostgresConnectionMaxIdle)
}

// GetPostgresConnectionMaxOpen returns the max number of open connections that should be open in the database connection pool.
// -1 represents no restrictions/default behavior
func (c *ConfigurationData) GetPostgresConnectionMaxOpen() int {
	return c.v.GetInt(varPostgresConnectionMaxOpen)
}

// GetPostgresConfigString returns a ready to use string for usage in sql.Open()
func (c *ConfigurationData) GetPostgresConfigString() string {
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

// GetHTTPAddress returns the HTTP address (as set via default, config file, or environment variable)
// that the auth server binds to (e.g. "0.0.0.0:8089")
func (c *ConfigurationData) GetHTTPAddress() string {
	return c.v.GetString(varHTTPAddress)
}

// GetHeaderMaxLength returns the max length of HTTP headers allowed in the system
// For example it can be used to limit the size of bearer tokens returned by the api service
func (c *ConfigurationData) GetHeaderMaxLength() int64 {
	return c.v.GetInt64(varHeaderMaxLength)
}

// IsPostgresDeveloperModeEnabled returns if development related features (as set via default, config file, or environment variable),
// e.g. token generation endpoint are enabled
func (c *ConfigurationData) IsPostgresDeveloperModeEnabled() bool {
	return c.v.GetBool(varDeveloperModeEnabled)
}

// IsCleanTestDataEnabled returns `true` if the test data should be cleaned after each test. (default: true)
func (c *ConfigurationData) IsCleanTestDataEnabled() bool {
	return c.v.GetBool(varCleanTestDataEnabled)
}

// IsCleanTestDataErrorReportingRequired returns `true` if there is any error while cleaning test data after each test. (default: true)
func (c *ConfigurationData) IsCleanTestDataErrorReportingRequired() bool {
	return c.v.GetBool(varCleanTestDataErrorReportingRequired)
}

// IsDBLogsEnabled returns `true` if the DB logs (ie, SQL queries) should be output in the console. (default: false)
func (c *ConfigurationData) IsDBLogsEnabled() bool {
	return c.v.GetBool(varDBLogsEnabled)
}

// GetCacheControlUsers returns the value to set in the "Cache-Control" HTTP response header
// when returning users.
func (c *ConfigurationData) GetCacheControlUsers() string {
	return c.v.GetString(varCacheControlUsers)
}

// GetCacheControlCollaborators returns the value to set in the "Cache-Control" HTTP response header
// when returning collaborators.
func (c *ConfigurationData) GetCacheControlCollaborators() string {
	return c.v.GetString(varCacheControlCollaborators)
}

// GetCacheControlUser returns the value to set in the "Cache-Control" HTTP response header
// when data for the current user.
func (c *ConfigurationData) GetCacheControlUser() string {
	return c.v.GetString(varCacheControlUser)
}

// GetUserAccountPrivateKey returns the user account private key and its ID
// that is used to sign user access and refresh tokens.
func (c *ConfigurationData) GetUserAccountPrivateKey() ([]byte, string) {
	return []byte(c.v.GetString(varUserAccountPrivateKey)), c.v.GetString(varUserAccountPrivateKeyID)
}

// GetAccessTokenExpiresIn returns lifespan of user access tokens generated by Auth in seconds
func (c *ConfigurationData) GetAccessTokenExpiresIn() int64 {
	return c.v.GetInt64(varAccessTokenExpiresIn)
}

// GetRefreshTokenExpiresIn returns lifespan of user refresh tokens generated by Auth in seconds
func (c *ConfigurationData) GetRefreshTokenExpiresIn() int64 {
	return c.v.GetInt64(varRefreshTokenExpiresIn)
}

// GetDevModePublicKey returns additional public key and its ID which should be used by the Auth service in Dev Mode
// For example a public key from Keycloak
// Returns false if in in Dev Mode
func (c *ConfigurationData) GetDevModePublicKey() (bool, []byte, string) {
	if c.IsPostgresDeveloperModeEnabled() {
		return true, []byte(devModePublicKey), devModePublicKeyID
	}
	return false, nil, ""
}

// GetNotApprovedRedirect returns the URL to redirect to if the user is not approved
// May return empty string which means an unauthorized error should be returned instead of redirecting the user
func (c *ConfigurationData) GetNotApprovedRedirect() string {
	return c.v.GetString(varNotApprovedRedirect)
}

// GetOAuthProviderClientSecret returns the oauth client secret (as set via config file or environment variable)
// that is used to make authorized API Calls to the OAuth authentication provider.
func (c *ConfigurationData) GetOAuthProviderClientSecret() string {
	return c.v.GetString(varOAuthProviderClientSecret)
}

// GetOAuthClientID returns the oauth client ID (as set via config file or environment variable)
// that is used to make authorized API Calls to the OAuth authentication provider.
func (c *ConfigurationData) GetOAuthProviderClientID() string {
	return c.v.GetString(varOAuthProviderClientID)
}

// GetPublicOAuthClientID returns the public clientID
func (c *ConfigurationData) GetPublicOAuthClientID() string {
	return c.v.GetString(varPublicOAuthClientID)
}

func (c *ConfigurationData) GetOAuthProviderType() string {
	return c.v.GetString(varOAuthProviderType)
}

// GetOAuthProviderEndpointAuth returns the auth provider endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetOAuthProviderEndpointAuth() string {
	return c.v.GetString(varOAuthProviderEndpointAuth)
}

// GetOAuthProviderEndpointToken returns the auth provider token endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetOAuthProviderEndpointToken() string {
	return c.v.GetString(varOAuthProviderEndpointToken)
}

// GetOAuthProviderEndpointUserInfo returns the auth provider userinfo endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetOAuthProviderEndpointUserInfo() string {
	return c.v.GetString(varOAuthProviderEndpointUserInfo)
}

// GetOAuthProviderEndpointLogout returns the auth provider logout endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetOAuthProviderEndpointLogout() string {
	return c.v.GetString(varOAuthProviderEndpointLogout)
}

func (c *ConfigurationData) GetOAuthProviderScopes() string {
	return c.v.GetString(varOAuthProviderScopes)
}

// GetLogLevel returns the logging level (as set via config file or environment variable)
func (c *ConfigurationData) GetLogLevel() string {
	return c.v.GetString(varLogLevel)
}

// IsLogJSON returns if we should log json format (as set via config file or environment variable)
func (c *ConfigurationData) IsLogJSON() bool {
	if c.v.IsSet(varLogJSON) {
		return c.v.GetBool(varLogJSON)
	}
	if c.IsPostgresDeveloperModeEnabled() {
		return false
	}
	return true
}

// GetValidRedirectURLs returns the RegEx of valid redirect URLs for auth requests
// If AUTH_REDIRECT_VALID is not set then in Dev Mode all redirects allowed - *
// Otherwise only *.openshift.io URLs are considered valid
func (c *ConfigurationData) GetValidRedirectURLs() string {
	if c.v.IsSet(varValidRedirectURLs) {
		return c.v.GetString(varValidRedirectURLs)
	}
	if c.IsPostgresDeveloperModeEnabled() {
		return devModeValidRedirectURLs
	}
	return DefaultValidRedirectURLs
}

func (c *ConfigurationData) GetExpiredTokenRetentionHours() int {
	return c.v.GetInt(varExpiredTokenRetentionHours)
}

func (c *ConfigurationData) GetPrivilegeCacheExpirySeconds() int64 {
	return c.v.GetInt64(varPrivilegeCacheExpirySeconds)
}

func (c *ConfigurationData) GetRPTTokenMaxPermissions() int {
	return c.v.GetInt(varRPTTokenMaxPermissions)
}

func (c *ConfigurationData) GetBaseSiteURL() string {
	return c.v.GetString(varBaseSiteURL)
}

func (c *ConfigurationData) GetInstanceDescriptor() string {
	return c.v.GetString(varInstanceDescriptor)
}

func (c *ConfigurationData) GetRemoteIPHeader() string {
	return c.v.GetString(varRemoteIPHeader)
}
