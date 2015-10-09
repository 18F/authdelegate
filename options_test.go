package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func optionErrors(msgs []string) string {
	return "Invalid options:\n  " + strings.Join(msgs, "\n  ")
}

var _ = Describe("AuthDelegateOptions", func() {
	// Use the test source file as the SSL cert and key to enable file
	// existence validation to pass.
	cwd, _ := os.Getwd()
	filename := filepath.Join(cwd, "options_test.go")
	defaultConfig := []byte(strings.Join([]string{
		`{`,
		`  "port": 443,`,
		`  "ssl_cert": "` + filename + `",`,
		`  "ssl_key": "` + filename + `",`,
		`  "upstreams": [`,
		`    { "url": "https://foo.com/auth",`,
		`      "cookie_name": "_oauth2_proxy"`,
		`    },`,
		`    { "url": "http://127.0.0.1:8080/auth",`,
		`      "header_name": "X-Signature"`,
		`    },`,
		`    { "url": "https://foo.com/auth"`,
		`    }`,
		`  ]`,
		`}`,
	}, "\n"))

	It("should parse and validate the default JSON config", func() {
		opts, err := NewAuthDelegateOptionsFromJSON(defaultConfig)
		Expect(err).To(BeNil())
		Expect(opts).ToNot(BeNil())
		fooURL, _ := url.Parse("https://foo.com/auth")
		localhostURL, _ := url.Parse("http://127.0.0.1:8080/auth")
		Expect(*opts).To(Equal(AuthDelegateOptions{
			Port:    443,
			SslCert: filename,
			SslKey:  filename,
			Upstreams: []*AuthDelegateUpstream{
				&AuthDelegateUpstream{
					URL:        fooURL.String(),
					HeaderName: "",
					CookieName: "_oauth2_proxy",
					parsedURL:  fooURL,
				},
				&AuthDelegateUpstream{
					URL:        localhostURL.String(),
					HeaderName: "X-Signature",
					CookieName: "",
					parsedURL:  localhostURL,
				},
				&AuthDelegateUpstream{
					URL:        fooURL.String(),
					HeaderName: "",
					CookieName: "",
					parsedURL:  fooURL,
				},
			},
		}))
	})

	It("should return an error if JSON parsing fails", func() {
		opts, err := NewAuthDelegateOptionsFromJSON(defaultConfig[1:])
		Expect(opts).To(BeNil())
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(HavePrefix("JSON parsing failed: "))
	})

	It("should return an error if validation fails", func() {
		badConfig := []byte(strings.Join([]string{
			`{`,
			`  "port": 0,`,
			`  "ssl_cert": "./bogus.crt",`,
			`  "ssl_key": "./bogus.key",`,
			`  "upstreams": [`,
			`    { "url": "https://foo.com/auth",`,
			`      "cookie_name": "_oauth2_proxy",`,
			`      "header_name": "X-Signature"`,
			`    },`,
			`    { "url": "http://127.0.0.1:8080/auth"`,
			`    },`,
			`    { "url": "https://foo.com/auth"`,
			`    }`,
			`  ]`,
			`}`,
		}, "\n"))
		opts, err := NewAuthDelegateOptionsFromJSON(badConfig)
		Expect(opts).To(BeNil())
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(Equal(strings.Join([]string{
			"Invalid options:",
			"port must be specified and greater than zero",
			"ssl-cert does not exist: ./bogus.crt",
			"ssl-key does not exist: ./bogus.key",
			"both header_name and cookie_name defined: " +
				"https://foo.com/auth",
			"multiple upstreams without header_name or cookie_name",
		}, "\n  ")))
	})

	It("should fail validation if no upstreams defined", func() {
		opts, err := NewAuthDelegateOptionsFromJSON(
			[]byte(`{"port": 443}`))
		Expect(opts).To(BeNil())
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(Equal(strings.Join([]string{
			"Invalid options:",
			"no upstreams defined",
		}, "\n  ")))
	})

	It("should fail validation if upstream URLs are malformed", func() {
		badConfig := []byte(strings.Join([]string{
			`{`,
			`  "port": 443,`,
			`  "upstreams": [`,
			`    { "url": "foo.com/auth",`,
			`      "cookie_name": "_oauth2_proxy"`,
			`    },`,
			`    { "url": "gopher://127.0.0.1:8080/auth",`,
			`      "header_name": "X-Signature"`,
			`    }`,
			`  ]`,
			`}`,
		}, "\n"))
		opts, err := NewAuthDelegateOptionsFromJSON(badConfig)
		Expect(opts).To(BeNil())
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(Equal(strings.Join([]string{
			"Invalid options:",
			"upstream scheme not specified: foo.com/auth",
			"invalid upstream scheme: gopher://127.0.0.1:8080/auth",
		}, "\n  ")))
	})

	It("should fail validation if a default upstream isn't last", func() {
		badConfig := []byte(strings.Join([]string{
			`{`,
			`  "port": 443,`,
			`  "upstreams": [`,
			`    { "url": "https://foo.com/auth"`,
			`    },`,
			`    { "url": "http://127.0.0.1:8080/auth",`,
			`      "header_name": "X-Signature"`,
			`    }`,
			`  ]`,
			`}`,
		}, "\n"))
		opts, err := NewAuthDelegateOptionsFromJSON(badConfig)
		Expect(opts).To(BeNil())
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(Equal(strings.Join([]string{
			"Invalid options:",
			"upstream without header_name or cookie_name not " +
				"last in upstream list: https://foo.com/auth",
		}, "\n  ")))
	})

	It("should fail validation if a cookie or header is repeated", func() {
		badConfig := []byte(strings.Join([]string{
			`{`,
			`  "port": 443,`,
			`  "upstreams": [`,
			`    { "url": "https://foo.com/auth",`,
			`      "header_name": "X-Signature"`,
			`    },`,
			`    { "url": "http://bar.com/auth",`,
			`      "header_name": "X-Signature"`,
			`    },`,
			`    { "url": "https://baz.com/auth",`,
			`      "cookie_name": "_cookie"`,
			`    },`,
			`    { "url": "http://quux.com/auth",`,
			`      "cookie_name": "_cookie"`,
			`    }`,
			`  ]`,
			`}`,
		}, "\n"))
		opts, err := NewAuthDelegateOptionsFromJSON(badConfig)
		Expect(opts).To(BeNil())
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(Equal(strings.Join([]string{
			"Invalid options:",
			"repeated cookie names: _cookie",
			"repeated header names: X-Signature",
		}, "\n  ")))
	})

	It("should fail validation if a cert specified, but no key", func() {
		badConfig := []byte(strings.Join([]string{
			`{`,
			`  "port": 443,`,
			`  "ssl_cert": "` + filename + `",`,
			`  "upstreams": [`,
			`    { "url": "https://foo.com/auth" }`,
			`  ]`,
			`}`,
		}, "\n"))
		opts, err := NewAuthDelegateOptionsFromJSON(badConfig)
		Expect(opts).To(BeNil())
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(Equal(strings.Join([]string{
			"Invalid options:",
			"ssl-cert and ssl-key must both be " +
				"specified, or neither must be",
		}, "\n  ")))
	})

	It("should fail validation if a key specified, but no cert", func() {
		badConfig := []byte(strings.Join([]string{
			`{`,
			`  "port": 443,`,
			`  "ssl_key": "` + filename + `",`,
			`  "upstreams": [`,
			`    { "url": "https://foo.com/auth" }`,
			`  ]`,
			`}`,
		}, "\n"))
		opts, err := NewAuthDelegateOptionsFromJSON(badConfig)
		Expect(opts).To(BeNil())
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(Equal(strings.Join([]string{
			"Invalid options:",
			"ssl-cert and ssl-key must both be " +
				"specified, or neither must be",
		}, "\n  ")))
	})
})
