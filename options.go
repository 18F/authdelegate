package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
)

// AuthDelegateOptions contains the parameters needed to determine which
// authentication handler to launch and to configure it properly.
type AuthDelegateOptions struct {
	// Port on which to listen for requests
	Port int `json:"port"`

	// Path to the server's SSL certificate
	SslCert string `json:"ssl_cert"`

	// Path to the key for -ssl-cert
	SslKey string `json:"ssl_key"`

	// Signed/authenticated requests are proxied to these servers based on
	// a match with each upstream's HeaderName or CookieName. The server
	// will send the request to the first upstream that matches one of its
	// headers, one of its cookies, or that doesn't define either
	// HeaderName or CookieName.
	//
	// To have a "default" server, make it the final item, and don't
	// define the HeaderName or CookieName.
	Upstreams []*AuthDelegateUpstream `json:"upstreams"`
}

// AuthDelegateUpstream contains a raw URL string from the command line as
// well as its parsed representation.
type AuthDelegateUpstream struct {
	// Unparsed version of the upstream URL
	URL string `json:"url"`

	// Header that indicates that requests should be sent to this upstream
	HeaderName string `json:"header_name"`

	// CookieName that indicates that requests should be sent to this
	// upstream
	CookieName string `json:"cookie_name"`

	// Parsed version of the upstream URL
	parsedURL *url.URL
}

// NewAuthDelegateOptionsFromJSON parses the JSON stored in config into an
// AuthDelegateOptions structure, which is then validated. Returns nil and an
// error if the JSON fails to parse or if AuthDelegateOptions.Validate()
// fails.
func NewAuthDelegateOptionsFromJSON(config []byte) (
	*AuthDelegateOptions, error) {
	var opts AuthDelegateOptions
	if err := json.Unmarshal(config, &opts); err != nil {
		return nil, errors.New("JSON parsing failed: " + err.Error())
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return &opts, nil
}

// Validate ensures that the AuthDelegateOptions configuration is correct and
// parses some of the values into a useable format. It also sets the Mode
// member that determines which proxy handler to launch. Collects as many
// error messages as possible and returns them as a single string via the err
// return value.
func (opts *AuthDelegateOptions) Validate() (err error) {
	var msgs []string
	msgs = validatePort(opts, msgs)
	msgs = validateSsl(opts, msgs)
	msgs = validateUpstreams(opts, msgs)

	if len(msgs) != 0 {
		err = errors.New("Invalid options:\n  " +
			strings.Join(msgs, "\n  "))
	}
	return
}

func validatePort(opts *AuthDelegateOptions, msgs []string) []string {
	if opts.Port <= 0 {
		msgs = append(msgs, "port must be specified and "+
			"greater than zero")
	}
	return msgs
}

func checkExistenceAndPermission(path, optionName string,
	msgs []string) []string {
	if info, err := os.Stat(path); os.IsNotExist(err) {
		msgs = append(msgs, optionName+" does not exist: "+path)
	} else if os.IsPermission(err) {
		msgs = append(msgs, optionName+" permission is denied: "+path)
	} else if !info.Mode().IsRegular() {
		msgs = append(msgs, optionName+" is not a regular file: "+path)
	}
	return msgs
}

func validateSsl(opts *AuthDelegateOptions, msgs []string) []string {
	certSpecified := opts.SslCert != ""
	keySpecified := opts.SslKey != ""
	if !(certSpecified || keySpecified) {
		return msgs
	} else if !(certSpecified && keySpecified) {
		msgs = append(msgs, "ssl-cert and ssl-key must both be "+
			"specified, or neither must be")
	}

	if certSpecified {
		msgs = checkExistenceAndPermission(
			opts.SslCert, "ssl-cert", msgs)
	}
	if keySpecified {
		msgs = checkExistenceAndPermission(opts.SslKey, "ssl-key", msgs)
	}
	return msgs
}

func validateUpstreams(opts *AuthDelegateOptions, msgs []string) []string {
	if len(opts.Upstreams) == 0 {
		return append(msgs, "no upstreams defined")
	}

	numUpstreams := len(opts.Upstreams)
	var defaultUpstreams []string
	cookieNames := make(map[string]int)
	headerNames := make(map[string]int)

	for i := 0; i != numUpstreams; i++ {
		current := opts.Upstreams[i]
		msgs = validateUpstream(current, msgs)
		if current.HeaderName == "" && current.CookieName == "" {
			defaultUpstreams = append(defaultUpstreams, current.URL)
		}
		cookieNames[current.CookieName]++
		headerNames[current.HeaderName]++
	}
	msgs = validateNameCounts("cookie names", cookieNames, msgs)
	msgs = validateNameCounts("header names", headerNames, msgs)
	msgs = validateDefaultUpstreams(defaultUpstreams,
		opts.Upstreams[numUpstreams-1], msgs)
	return msgs
}

func validateUpstream(upstream *AuthDelegateUpstream, msgs []string) []string {
	var err error
	if upstream.parsedURL, err = url.Parse(upstream.URL); err != nil {
		msgs = append(msgs, "upstream URL failed to parse"+err.Error())
	}
	scheme := upstream.parsedURL.Scheme
	if scheme == "" {
		msgs = append(msgs, "upstream scheme not specified: "+
			upstream.URL)
	} else if !(scheme == "http" || scheme == "https") {
		msgs = append(msgs, "invalid upstream scheme: "+upstream.URL)
	}
	if upstream.HeaderName != "" && upstream.CookieName != "" {
		msgs = append(msgs, "both header_name and cookie_name "+
			"defined: "+upstream.URL)
	}
	return msgs
}

func validateNameCounts(category string, counts map[string]int,
	msgs []string) []string {
	var repeatedNames []string
	delete(counts, "")
	for name, numAppearances := range counts {
		if numAppearances > 1 {
			repeatedNames = append(repeatedNames, name)
		}
	}
	if len(repeatedNames) != 0 {
		msgs = append(msgs, "repeated "+category+": "+
			strings.Join(repeatedNames, ", "))
	}
	return msgs
}

func validateDefaultUpstreams(defaultUpstreams []string,
	lastUpstream *AuthDelegateUpstream, msgs []string) []string {
	numDefaults := len(defaultUpstreams)
	if numDefaults == 0 {
		return msgs
	}

	lastDefault := defaultUpstreams[numDefaults-1]
	if numDefaults > 1 {
		msgs = append(msgs, "multiple upstreams without header_name "+
			"or cookie_name")
	} else if lastDefault != lastUpstream.URL {
		msgs = append(msgs, "upstream without header_name "+
			"or cookie_name not last in upstream list: "+
			lastDefault)
	}
	return msgs
}
