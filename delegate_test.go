package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
)

var _ = Describe("AuthDelegate", func() {
	var req *http.Request
	var recorder *httptest.ResponseRecorder
	var opts *AuthDelegateOptions
	var servers []*httptest.Server

	BeforeEach(func() {
		req, _ = http.NewRequest("GET", "http://foo.com/", nil)
		recorder = httptest.NewRecorder()
		opts = &AuthDelegateOptions{}
	})

	AfterEach(func() {
		for i := len(servers) - 1; i != -1; i-- {
			servers[i].Close()
		}
	})

	addUpstream := func(httpStatus int, cookieName, headerName string) {
		handler := func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(httpStatus)
		}
		server := httptest.NewServer(http.HandlerFunc(handler))
		servers = append(servers, server)
		opts.Upstreams = append(opts.Upstreams, &AuthDelegateUpstream{
			URL:        server.URL,
			CookieName: cookieName,
			HeaderName: headerName,
		})
	}

	It("should return Unauthorized if no upstreams defined", func() {
		NewAuthDelegate(opts).ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
	})

	It("should return Unauthorized if no match and no default", func() {
		addUpstream(http.StatusAccepted, "", "X-Signature")
		addUpstream(http.StatusAccepted, "_cookie", "")
		_ = opts.Validate()
		NewAuthDelegate(opts).ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
	})

	It("should return Accepted from a default upstream", func() {
		addUpstream(http.StatusUnauthorized, "_cookie", "")
		addUpstream(http.StatusUnauthorized, "", "X-Signature")
		addUpstream(http.StatusAccepted, "", "")
		_ = opts.Validate()
		NewAuthDelegate(opts).ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(http.StatusAccepted))
	})

	It("should return Unauthorized from a default upstream", func() {
		addUpstream(http.StatusAccepted, "", "X-Signature")
		addUpstream(http.StatusAccepted, "_cookie", "")
		addUpstream(http.StatusUnauthorized, "", "")
		_ = opts.Validate()
		NewAuthDelegate(opts).ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
	})

	It("should return Accepted from a cookie-match upstream", func() {
		addUpstream(http.StatusAccepted, "_cookie", "")
		addUpstream(http.StatusUnauthorized, "", "X-Signature")
		addUpstream(http.StatusUnauthorized, "", "")
		_ = opts.Validate()
		req.AddCookie(&http.Cookie{Name: "_cookie"})
		NewAuthDelegate(opts).ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(http.StatusAccepted))
	})

	It("should return Unauthorized from a cookie-match upstream", func() {
		addUpstream(http.StatusAccepted, "", "X-Signature")
		addUpstream(http.StatusUnauthorized, "_cookie", "")
		addUpstream(http.StatusAccepted, "", "")
		_ = opts.Validate()
		req.AddCookie(&http.Cookie{Name: "_cookie"})
		NewAuthDelegate(opts).ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
	})

	It("should return Accepted from a header-match upstream", func() {
		addUpstream(http.StatusUnauthorized, "_cookie", "")
		addUpstream(http.StatusAccepted, "", "X-Signature")
		addUpstream(http.StatusUnauthorized, "", "")
		_ = opts.Validate()
		req.Header.Set("X-Signature", "foobar")
		NewAuthDelegate(opts).ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(http.StatusAccepted))
	})

	It("should return Unauthorized from a header-match upstream", func() {
		addUpstream(http.StatusUnauthorized, "", "X-Signature")
		addUpstream(http.StatusAccepted, "_cookie", "")
		addUpstream(http.StatusAccepted, "", "")
		_ = opts.Validate()
		req.Header.Set("X-Signature", "foobar")
		NewAuthDelegate(opts).ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
	})

	It("should match the first upstream if both cookie and header", func() {
		addUpstream(http.StatusAccepted, "", "X-Signature")
		addUpstream(http.StatusUnauthorized, "_cookie", "")
		_ = opts.Validate()
		req.AddCookie(&http.Cookie{Name: "_cookie"})
		req.Header.Set("X-Signature", "foobar")
		NewAuthDelegate(opts).ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(http.StatusAccepted))
	})

	// For the following tests, we need to launch a server rather than
	// test the AuthDelegate handler directly, so that req.RequestURI is
	// parsed as it would be in a live server.
	addUpstreamGrabOriginalURI := func() *string {
		var xOriginalURI string
		handler := func(rw http.ResponseWriter, req *http.Request) {
			xOriginalURI = req.Header.Get("X-Original-URI")
			rw.WriteHeader(http.StatusAccepted)
		}
		server := httptest.NewServer(http.HandlerFunc(handler))
		servers = append(servers, server)
		opts.Upstreams = append(opts.Upstreams,
			&AuthDelegateUpstream{URL: server.URL})
		return &xOriginalURI
	}

	launchAuthDelegateServer := func() *httptest.Server {
		server := httptest.NewServer(NewAuthDelegate(opts))
		servers = append(servers, server)
		return server
	}

	It("should set X-Original-URI if not set", func() {
		xOriginalURI := addUpstreamGrabOriginalURI()
		_ = opts.Validate()
		authDelegate := launchAuthDelegateServer()
		req, _ = http.NewRequest(
			"GET", authDelegate.URL+"/bar?quux", nil)
		response, err := http.DefaultClient.Do(req)
		Expect(err).To(BeNil())
		Expect(response.StatusCode).To(Equal(http.StatusAccepted))
		Expect(*xOriginalURI).To(Equal("/bar?quux"))
	})

	It("should not update X-Original-URI if already set", func() {
		xOriginalURI := addUpstreamGrabOriginalURI()
		_ = opts.Validate()
		authDelegate := launchAuthDelegateServer()
		req, _ = http.NewRequest(
			"GET", authDelegate.URL+"/bar", nil)
		req.Header.Set("X-Original-URI", "/baz?quux")
		response, err := http.DefaultClient.Do(req)
		Expect(err).To(BeNil())
		Expect(response.StatusCode).To(Equal(http.StatusAccepted))
		Expect(*xOriginalURI).To(Equal("/baz?quux"))
	})
})
