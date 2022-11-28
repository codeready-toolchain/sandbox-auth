package configuration

const (
	defaultHeaderMaxLength = 5000 // bytes

	DefaultUserAccountPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA40yB6SNoU4SpWxTfG5ilu+BlLYikRyyEcJIGg//w/GyqtjvT
/CVo92DRTh/DlrgwjSitmZrhauBnrCOoUBMin0/TXeSo3w2M5tEiiIFPbTDRf2jM
fbSGEOke9O0USCCR+bM2TncrgZR74qlSwq38VCND4zHc89rAzqJ2LVM2aXkuBbO7
TcgLNyooBrpOK9khVHAD64cyODAdJY4esUjcLdlcB7TMDGOgxGGn2RARU7+TUf32
gZZbTMikbuPM5gXuzGlo/22ECbQSKuZpbGwgPIAZ5NN9QA4D1NRz9+KDoiXZ6deZ
TTVCrZykJJ6RyLNfRh+XS+6G5nvcqAmfBpyOWwIDAQABAoIBAE5pBie23zZwfTu+
Z3jNn96/+idLC+DBqq5qsXS3xhpOIlXbLbW98gfkjk+1BXPo9la7wadLlpeX8iuf
4WA+OaNblj69ssO/mOvHGXKdqRixzpN1Q5XZwKX0xYkYf/ahxbmt6P4IfimlX1dB
shsWigU8ZR7rBJ3ayMh/ouTf39ViIbXsHYpEubmACcLaOlXbEuZNr7ofkFQKl/mh
XLWUeOoM97xY6Agw/gv60GIcxIC5OAg7iNqS+XNzhba7f2nf2YqodbN9H1BmEJsf
RRaTTWlZAiQXC8lpZOKwP7DiMLOT78lfmlYtquEBhwRbXazfzsdf67Mr4Kdl2Cej
Jy0EGwECgYEA/DZWB0Lb0tPdT1FmORNrBfGg3PjhX9FOilhbtUgX3nNKp8Zsi3yO
yN6hf0/98qIGlmAQi5C92cXpdhqTiVAGktWD+q0a1W99udIjinS1tFrKgNtOyBWN
uwDBZyhw8RrwpQinMe7B966SVDaphvvOWlB1TadMDh5kReJCYpvRCrMCgYEA5rZj
djCU2UqMw6jIP07nCFjWgxPPjg7jP8aRo07oW2mv1sEA0doCyoZaMrdNeGd3fB0B
sm+IvlQtWD7r0tWZI1GkYpdRkDFurdkIzVPV5pMwH4ByOq/Jf5ZqtjIpoMaRBirA
whJyjmiGU3yDyPDLtEFpNgqM3mIyxS6M6UGKYbkCgYEAg6w+d6YBK+1uQiXGD5BC
tKS0jgjlaOfWcEW3A0qzI3Dfjf3610vdI6OPfu8dLppGhCV9HdAgPdykiQNQ+UQt
WmVcdPgA5WNCqUu7QGK0Joer52AXnkAacYHwdtHXPRkKf66n01rKK2wZexvan91A
m0gcJcFs5IYbZZy9ecvNdB8CgYEAo4JZ5Vay93j1YGnLWcrixDCp/wXYUJbOidGC
QBpZZQf3Hh11JkT7O2uSm2T727yAmw63uC2B3VotNOCLI8ZMHRLsjQ8vOCFAjqdF
rLeg3iQss/bFfkA9b1Y8VNoiVJbGC3fbWu/WDoWXxa12fL/jruG43hsGEUnJL6Q5
K8tOdskCgYABpoHFRxsvJ5Sp9CUS3BBTicVSkpAjoX2O3+cS9XL8IsIqZEMW7VKb
16/H2BRvI0uUq12t+UCc0P0SyrWRGxwGR5zSYHVDOot5EDHqE8aYSbX4jiXtAAiu
qCn3Rug8QWyBjjxnU3CxPRiLSmEllQAAVlzfRWn6kL4RKSyruUhZaA==
-----END RSA PRIVATE KEY-----`

	defaultUserAccountPrivateKeyID = "aUGv8mQA85jg4V1DU8Uk1W0uKsxn187KQONAGl6AMtc"

	devModePublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvQ8p+HsTMrgcsuIMoOR1
LXRhynL9YAU0qoDON6PLKCpdBv0Xy/jnsPjo5DrtUOijuJcID8CR7E0hYpY9MgK5
H5pDFwC4lbUVENquHEVS/E0pQSKCIzSmORcIhjYW2+wKfDOVjeudZwdFBIxJ6KpI
ty/aF78hlUJZuvghFVqoHQYTq/DZOmKjS+PAVLw8FKE3wa/3WU0EkpP+iovRMCkl
lzxqrcLPIvx+T2gkwe0bn0kTvdMOhTLTN2tuvKrFpVUxVi8RM/V8PtgdKroxnES7
SyUqK8rLO830jKJzAYrByQL+sdGuSqInIY/geahQHEGTwMI0CLj6zfhpjSgCflst
vwIDAQAB
-----END RSA PUBLIC KEY-----`

	devModePublicKeyID = "bNq-BCOR3ev-E6buGSaPrU-0SXX8whhDlmZ6geenkTE"

	defaultDBPassword = "mysecretpassword"

	defaultLogLevel = "info"

	// Auth Provider defaults
	defaultOAuthProviderType         = "keycloak"
	defaultOAuthProviderClientID     = "devsandbox-online-platform"
	defaultOAuthProviderClientSecret = "c7b4487d-3d10-4f23-a163-c32450f3197b"

	defaultOAuthProviderEndpointAuth     = "https://sso.devsandbox.dev/auth/realms/sandbox-auth/protocol/openid-connect/auth"
	defaultOAuthProviderEndpointToken    = "https://sso.devsandbox.dev/auth/realms/sandbox-auth/protocol/openid-connect/token"
	defaultOAuthProviderEndpointUserInfo = "https://sso.devsandbox.dev/auth/realms/sandbox-auth/protocol/openid-connect/userinfo"
	defaultOAuthProviderEndpointLogout   = "https://sso.devsandbox.dev/auth/realms/sandbox-auth/protocol/openid-connect/logout"
	defaultOAuthProviderScopes           = "user:email"

	defaultPublicOAuthClientID = "740650a2-9c44-4db5-b067-a3d1b2cd2d01"

	// DefaultValidRedirectURLs is a regex to be used to whitelist redirect URL for auth
	// If the SANDBOX_AUTH_REDIRECT_VALID env var is not set then in Dev Mode all redirects allowed - *
	// In prod mode the following regex will be used by default:
	DefaultValidRedirectURLs = "^(https|http)://(([^/?#]+[.])?localhost)((/|:).*)?$" //"^(https|http)://(([^/?#]+[.])?(?i:openshift[.]io)|localhost)((/|:).*)?$" // *.openshift.io/* and localhost
	devModeValidRedirectURLs = ".*"

	// The number of hours to retain expired tokens.  After this time limit has been exceeded, the token may be cleaned up (deleted)
	defaultExpiredTokenRetentionHours = 24
)
