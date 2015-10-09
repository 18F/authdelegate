# authdelegate Authentication Delegate Server

[![Build Status](https://travis-ci.org/18F/authdelegate.svg?branch=master)](https://travis-ci.org/18F/authdelegate)

[![Coverage Status](https://coveralls.io/repos/18F/authdelegate/badge.svg?branch=master&service=github)](https://coveralls.io/github/18F/authdelegate?branch=master)

A server that routes authenticated requests to multiple authentication
servers based on the presence of specific headers or cookies in a request.

It is compatible with the [Nginx
`ngx_http_auth_request_module`](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
and its `auth_request` directive.

## Use case

Imagine a static site served by nginx that contains API endpoints that should
be authenticated both via [bitly/oauth2_proxy](https://github.com/bitly/oauth2_proxy)
(so normal users can see the JSON in a browser) and via
[18F/hmacproxy](https://github.com/18F/hmacproxy/) (so that programs can
access the endpoints via HMAC-authenticated requests). This program allows you
to forward requests to both servers depending on whether any incoming request
has either an Oauth2 cookie or a header containing an HMAC signature.

_Note:_ While the primary use case is delegating `auth_request`s to multiple
authentication servers, the `authdelegate` could be used to proxy requests
generally.

## Installation

For now, install from source:

```sh
$ go get github.com/18F/authdelegate
```

## Configuration and execution

The `authdelegate` takes a single command line argument, a path to a JSON file
of configuration information. Example:

```json
{
  "port": 8080,
  "ssl_cert": "/path/to/ssl.cert",
  "ssl_key": "/path/to/ssl.key",
  "upstreams": [
    { "url": "http://127.0.0.1/oauth2/auth",
      "cookie_name": "_oauth2_proxy"
    },
    { "url": "http://127.0.0.1/hmacproxy/auth",
      "header_name": "X-Hmac-Signature"
    },
    { "url": "http://127.0.0.1/auth"
    }
  ]
}
```

The arguments are:

* **port**: the port number on which to run the service
* **ssl_cert** (optional): path to your server's SSL certificate
* **ssl_key** (optional): path to your server's SSL certificate key
* **upstreams**: list of servers to which requests will be forwarded
  * **url**: address of the upstream server
  * **header_name** (optional): the name of the header that signals that
    requests should be sent to this server
  * **cookie_name** (optional): the name of the cookie that signals that
    requests should be sent to this server

The rules are thus:

* If `ssl_cert` is specified, `ssl_key` must be specified as well, and vice
  versa.
* There must be at least one entry in `upstreams`.
* Upstream servers are checked in the order in which they are specified.
  * i.e. If a request has both a header and a cookie that matches more than
    one defined upstream server, it will be forwarded to the server that
    appears first in the list.
* No two upstreams can specify the same `header_name` or `cookie_name`.
* Only one of `header_name` or `cookie_name` can be specified per upstream.
* There can be at most one upstream with neither header_name` nor
  `cookie_name` specified, and it must be the last entry in `upstreams`,
  as all requests not matching earlier upstreams will be forwarded to this
  "default" upstream.
* If there is not a default upstream, and a request does not match any other
  defined upstreams, a 401 response (`http.StatusUnauthorized`) will be
  returned.
* The `X-Original-URI` header will be added to all forwarded requests, unless
  the header is already defined in the original request.

## Nginx configuration

Add configuration such as the following to your nginx instance, where:

- `PORT` is replaced with the port number of your service
- `myservice.com` is replaced with the virtual server name for your service
- `ssl/star.myservice.com.conf` contains the SSL configuration for your
  server.
- `http://127.0.0.1:8080` matches the address of the local `authdelegate`
  instance from above
- The `X-Original-URI` header is added to the authentication request, defined
  using [the builtin `$request_uri` nginx
  variable](http://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_uri).

```
server {
  listen PORT ssl spdy;
  server_name  myservice.com;

  include ssl/star.myservice.com.conf;

  location / {
    auth_request /auth;
    auth_request_set $http_set_cookie $upstream_http_set_cookie;
    ...
  }

  location = /auth {
    internal;
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Original-URI $request_uri;
  }
}
```

## Accepting incoming requests over SSL

If you wish to expose the delegate directly to the public, rather than via an
Nginx proxy scheme, pass the `-ssl-cert` and `-ssl-key` options along all
other `-auth` parameters.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0
>dedication. By submitting a pull request, you are agreeing to comply
>with this waiver of copyright interest.
