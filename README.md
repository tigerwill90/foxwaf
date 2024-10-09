[![Go Reference](https://pkg.go.dev/badge/github.com/tigerwill90/foxwaf.svg)](https://pkg.go.dev/github.com/tigerwill90/foxwaf)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/tigerwill90/foxwaf)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/tigerwill90/foxwaf)

# FoxWAF

FoxWAF is a middleware for the [Fox](https://github.com/tigerwill90/fox) router that integrates the 
[Coraza Web Application Firewall (WAF)](https://coraza.io/) to enhance the security of your web applications by intercepting 
and analyzing HTTP requests and responses.

### Disclaimer
FoxWAF's API is closely tied to the Fox router, and it will only reach v1 when the router is stabilized. During the pre-v1 phase, 
breaking changes may occur and will be documented in the release notes.

### Getting Started
Installation
````sh
go get -u github.com/tigerwill90/foxwaf
````

### Features
- Enhanced Security: Integrates Coraza WAF to protect your web application from a variety of web attacks.
- Seamless Integration: Tightly integrates with the Fox ecosystem for enhanced performance and scalability.
- Customizable: Allows for custom security rules and configurations to suit specific use cases.

### Usage
Here is an example to load [OWASP CRS](https://coreruleset.org/) using [coraza-coreruleset](https://github.com/corazawaf/coraza-coreruleset).
````go
package main

import (
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/tigerwill90/fox"
	"github.com/tigerwill90/foxwaf"
	"net/http"
)



func main() {

	cfg := coraza.NewWAFConfig().
		WithDirectives("Include @coraza.conf-recommended").
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf").
		WithDirectives("SecRuleEngine On").
		WithRootFS(coreruleset.FS)

	waf, _ := coraza.NewWAF(cfg)

	f := fox.New(
		fox.DefaultOptions(),
		fox.WithMiddleware(foxwaf.Middleware(waf)),
	)
	
	f.MustHandle(http.MethodGet, "/hello/{name}", func(c fox.Context) {
		_ = c.String(http.StatusOK, "Hello, %s", c.Param("name"))
	})


	_ = http.ListenAndServe(":8080", f)
}
````

````sh
curl -sS -D - "http://localhost:8080/hello/fox?path=../foo"
# HTTP/1.1 403 Forbidden
# Date: Mon, 15 Jul 2024 14:52:24 GMT
# Content-Length: 0
````
