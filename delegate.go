package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewAuthDelegate creates a http.Handler that demultiplexes requests based on
// the configuration of opts.Upstreams.
func NewAuthDelegate(opts *AuthDelegateOptions) http.Handler {
	var handler authDelegateHandler
	for _, upstream := range opts.Upstreams {
		handler.upstreams = append(handler.upstreams, authDelegate{
			upstream.HeaderName,
			upstream.CookieName,
			newAuthDelegateReverseProxy(upstream.parsedURL),
		})
	}
	return &handler
}

type authDelegateHandler struct {
	upstreams []authDelegate
}

func (handler authDelegateHandler) ServeHTTP(
	rw http.ResponseWriter, req *http.Request) {
	for _, upstream := range handler.upstreams {
		if upstream.accepts(req) {
			upstream.handler.ServeHTTP(rw, req)
			return
		}
	}
	http.Error(rw, "unauthorized request", http.StatusUnauthorized)
}

type authDelegate struct {
	headerName string
	cookieName string
	handler    http.Handler
}

func (delegate authDelegate) accepts(req *http.Request) bool {
	if delegate.headerName != "" {
		return req.Header.Get(delegate.headerName) != ""
	} else if delegate.cookieName != "" {
		_, err := req.Cookie(delegate.cookieName)
		return err != http.ErrNoCookie
	}
	return true
}

func newAuthDelegateReverseProxy(url *url.URL) (proxy *httputil.ReverseProxy) {
	proxy = httputil.NewSingleHostReverseProxy(url)
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		origURI := req.Header.Get("X-Original-URI")
		if origURI == "" {
			origURI = req.RequestURI
			req.Header.Set("X-Original-URI", origURI)
		}
		log.Printf("auth %s via %s\n", origURI, url.String())
		req.URL = url
	}
	return
}
