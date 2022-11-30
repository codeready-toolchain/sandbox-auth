package rest

import (
	"bytes"
	"context"
	"fmt"
	"github.com/codeready-toolchain/sandbox-auth/pkg/errors"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/http/middleware"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Doer is a wrapper interface for goa client Doer
type HttpDoer interface {
	goahttp.Doer
}

// HttpClient defines the Do method of the http client.
type HttpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type configuration interface {
	IsPostgresDeveloperModeEnabled() bool
}

// HttpClientDoer implements HttpDoer
type HttpClientDoer struct {
	HttpClient HttpClient
}

// DefaultHttpDoer creates a new HttpDoer with default http client
func DefaultHttpDoer() HttpDoer {
	return &HttpClientDoer{HttpClient: http.DefaultClient}
}

// Do overrides Do method of the default goa client Doer. It's needed for mocking http clients in tests.
func (d *HttpClientDoer) Do(req *http.Request) (*http.Response, error) {
	return d.HttpClient.Do(req)
}

// Host returns the host from the given request if run in prod mode or if config is nil
// and "auth.openshift.io" if run in dev mode
func Host(ctx context.Context, config configuration) string {
	host := ctx.Value(middleware.RequestHostKey).(string)
	return host
}

// AbsoluteURL prefixes a relative URL with absolute address
// If config is not nil and run in dev mode then host is replaced by "auth.openshift.io"
func AbsoluteURL(ctx context.Context, url *url.URL, relative string, config configuration) string {
	host := Host(ctx, config)
	return absoluteURLForHost(ctx, url, host, relative)
}

// ReplaceDomainPrefixInAbsoluteURL replaces the last name in the host of the URL by a new name.
// Example: https://api.service.domain.org -> https://sso.service.domain.org
// If replaceBy == "" then return trim the last name.
// Example: https://api.service.domain.org -> https://service.domain.org
// Also prefixes a relative URL with absolute address
// If config is not nil and run in dev mode then "auth.openshift.io" is used as a host
/*
func ReplaceDomainPrefixInAbsoluteURL(req *goa.RequestData, replaceBy, relative string, config configuration) (string, error) {
	host := Host(req, config)
	if host == "" { // this happens for tests. See https://github.com/goadesign/goa/issues/1861
		return "", nil
	}
	newHost, err := ReplaceDomainPrefix(host, replaceBy)
	if err != nil {
		return "", err
	}
	return absoluteURLForHost(req, newHost, relative), nil
}
*/

func absoluteURLForHost(ctx context.Context, url *url.URL, host, relative string) string {
	scheme := "http"
	if url != nil && url.Scheme == "https" { // isHTTPS
		scheme = "https"
	}
	xForwardProto := ctx.Value(middleware.RequestXForwardedProtoKey).(string)
	if xForwardProto != "" {
		scheme = xForwardProto
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, relative)
}

// ReplaceDomainPrefix replaces the last name in the host by a new name. Example: api.service.domain.org -> sso.service.domain.org
// If replaceBy == "" then return trim the last name. Example: api.service.domain.org -> service.domain.org
func ReplaceDomainPrefix(host string, replaceBy string) (string, error) {
	split := strings.SplitN(host, ".", 2)
	if len(split) < 2 {
		return host, errors.NewBadParameterError("host", host).Expected("must contain more at least one subdomain")
	}
	if replaceBy == "" {
		return split[1], nil
	}
	return replaceBy + "." + split[1], nil
}

// ReadBody reads body from a ReadCloser and returns it as a string
func ReadBody(body io.ReadCloser) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(body)
	return buf.String()
}

// CloseResponse reads the body and close the response. To be used to prevent file descriptor leaks.
func CloseResponse(response *http.Response) {
	ioutil.ReadAll(response.Body)
	response.Body.Close()
}

// ValidateEmail return true if the string is a valid email address
// This is a very simple validation. It just checks if there is @ and dot in the address
func ValidateEmail(email string) (bool, error) {
	// .+@.+\..+
	return regexp.MatchString(".+@.+\\..+", email)
}

// AddParam adds a parameter to URL
func AddParam(urlString string, paramName string, paramValue string) (string, error) {
	return AddParams(urlString, map[string]string{paramName: paramValue})
}

// AddParams adds parameters to URL
func AddParams(urlString string, params map[string]string) (string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	parameters := parsedURL.Query()
	for k, v := range params {
		parameters.Add(k, v)
	}
	parsedURL.RawQuery = parameters.Encode()

	return parsedURL.String(), nil
}

// AddTrailingSlashToURL adds a trailing slash to the URL if it doesn't have it already
// If URL is an empty string the function returns an empty string too
func AddTrailingSlashToURL(url string) string {
	if url != "" && !strings.HasSuffix(url, "/") {
		return url + "/"
	}
	return url
}
