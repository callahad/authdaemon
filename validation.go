package main

import (
	"net/url"
	"regexp"
	"strings"
)

// emailRE is used for basic validation and sanity-checking of email addresses.
// This pattern may exclude some legitimate addresses. Suggestions welcome.
var emailRE = regexp.MustCompile(`^[a-zA-Z0-9][+-_.a-zA-Z0-9]*@[-_.a-zA-Z0-9]+$`)

// hostRE is used for basic validation and sanity-checking of host components.
// For simplicity, this pattern excludes raw IPv6 literals. Oh well.
var hostRE = regexp.MustCompile(`^[\-.a-zA-Z0-9]+(:[0-9]+)?$`)

// validURI ensures that URIs are valid and conform to our expectations.
func validURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}

	tests := []bool{
		// The URL must parse as a host, port, etc. not just as opaque data.
		u.Opaque == "",

		// The scheme must be HTTP or HTTPS.
		u.Scheme == "http" || u.Scheme == "https",

		// The host must not redundantly specify default port numbers.
		!(u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")),
		!(u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")),

		// The hostname must be specified.
		hostRE.MatchString(u.Host),

		// The URL must not have a user:password prefix
		u.User == nil,

		// The URL struct also has Path, RawPath, RawQuery, and Fragment fields.
		// We don't care about these when assessing the basic validity of a URL.
	}

	for _, ok := range tests {
		if !ok {
			return false
		}
	}

	return true
}

// onlyOrigin checks that a URL is valid and only has a scheme, host, and port.
func onlyOrigin(uri string) bool {
	u, err := url.Parse(uri)

	if err != nil || !validURI(uri) || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}

	return true
}

// containedBy checks that a given URL is within a given origin.
func containedBy(uri string, origin string) bool {
	if !validURI(origin) || !validURI(uri) {
		return false
	}

	if !onlyOrigin(origin) {
		return false
	}

	a, err := url.Parse(uri)
	if err != nil {
		return false
	}

	b, err := url.Parse(origin)
	if err != nil {
		return false
	}

	return a.Scheme == b.Scheme && a.Host == b.Host
}
