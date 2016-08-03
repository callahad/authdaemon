package main

import "testing"

func TestValidURI(t *testing.T) {
	validCases := []string{
		// HTTP
		"http://example.com",
		"http://localhost",
		"http://127.0.0.1",

		// HTTPS
		"https://example.com",
		"https://localhost",
		"https://127.0.0.1",

		// Non-default ports
		"http://example.com:8080",
		"http://127.0.0.1:8080",
		"http://example.com:443",
		"https://example.com:80",

		// Paths, query strings, and fragments
		"http://example.com:8080/path?foo=bar#baz",
		"http://example.com:8080/?foo=bar#baz",
		"http://example.com:8080/#baz",
		"http://example.com:8080/path#baz",
		"http://example.com:8080/path?foo=bar",
	}

	invalidCases := []string{
		// Other Schemes
		"data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==",
		"ws://example.com",

		// Opaque Data
		"http:example.com",

		// Default ports
		"http://example.com:80",
		"https://example.com:443",

		// Userinfo
		"http://user:pass@example.com",
		"http://user@example.com",
		"http://@example.com",

		// Missing host
		"http://",
		"http:///path",
		"http://:8080",
		"http://:8080/path",

		// Invalid ports
		// TODO: Make these fail validation
		// "http://example.com:0",
		// "http://example.com:65536",

		// Invalid IPv6 literals
		"http://::1",
		"http://::1:8080",

		// IPv6 literals which are technically valid, but supporting them would
		// make the validation more complex than it's likely worth.
		"http://[::1]",
		"http://[::1]:8080",
		"https://[::1]",

		// Weird strings
		"http://example.com:8080:8080",
		"http://:8080:8080",
		"http://^",
	}

	for _, uri := range validCases {
		if !validURI(uri) {
			t.Errorf("validURI(%q) unexpectedly returned false", uri)
		}
	}

	for _, uri := range invalidCases {
		if validURI(uri) {
			t.Errorf("validURI(%q) unexpectedly returned true", uri)
		}
	}
}

func TestOnlyOrigin(t *testing.T) {
	validCases := []string{
		// HTTP
		"http://example.com",
		"http://localhost",
		"http://127.0.0.1",

		// HTTPS
		"https://example.com",
		"https://localhost",
		"https://127.0.0.1",

		// Non-default ports
		"http://example.com:8080",
		"http://127.0.0.1:8080",
		"http://example.com:443",
		"https://example.com:80",
	}

	invalidCases := []string{
		// Other Schemes
		"data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==",
		"ws://example.com",

		// Opaque Data
		"http:example.com",

		// Default ports
		"http://example.com:80",
		"https://example.com:443",

		// Userinfo
		"http://user:pass@example.com",
		"http://user@example.com",
		"http://@example.com",

		// Missing host
		"http://",
		"http:///path",
		"http://:8080",
		"http://:8080/path",

		// Invalid IPv6 literals
		"http://::1",
		"http://::1:8080",

		// IPv6 literals which are technically valid, but supporting them would
		// make the validation more complex than it's likely worth.
		"http://[::1]",
		"http://[::1]:8080",
		"https://[::1]",

		// Weird strings
		"http://example.com:8080:8080",
		"http://:8080:8080",

		// Paths, query strings, and fragments
		"http://example.com:8080/",
		"http://example.com:8080/path?foo=bar#baz",
		"http://example.com:8080/?foo=bar#baz",
		"http://example.com:8080/#baz",
		"http://example.com:8080/path#baz",
		"http://example.com:8080/path?foo=bar",
	}

	for _, uri := range validCases {
		if !onlyOrigin(uri) {
			t.Errorf("onlyOrigin(%q) unexpectedly returned false", uri)
		}
	}

	for _, uri := range invalidCases {
		if onlyOrigin(uri) {
			t.Errorf("onlyOrigin(%q) unexpectedly returned true", uri)
		}
	}
}

func TestContainedBy(t *testing.T) {
	tests := []struct {
		url      string
		origin   string
		expected bool
	}{
		// Valid cases
		{
			"http://example.com",
			"http://example.com",
			true,
		},
		{
			"http://example.com/foo",
			"http://example.com",
			true,
		},

		// Invalid cases
		{
			"http://example.com^",
			"http://example.com",
			false,
		},
		{
			"http://example.com",
			"http://example.com^",
			false,
		},
		{
			"http://user:pass@example.com",
			"http://example.com",
			false,
		},
		{
			"http://example.com",
			"http://user:pass@example.com",
			false,
		},
		{
			"http://example.com",
			"http://example.com/foo",
			false,
		},
		{
			"http://example.com.evil.com",
			"http://example.com",
			false,
		},
		{
			"http://example.com@evil.com",
			"http://example.com",
			false,
		},
		{
			"http://example.com",
			"https://example.com",
			false,
		},
		{
			"http://example.com",
			"http://example.com:8080",
			false,
		},
		{
			"http://example.com:8080",
			"http://example.com",
			false,
		},
	}

	for _, test := range tests {
		actual := containedBy(test.url, test.origin)
		if actual != test.expected {
			t.Errorf("containedBy(%q, %q) returned %t instead of %t", test.url, test.origin, actual, test.expected)
		}
	}
}

func TestEmailRE(t *testing.T) {
	validCases := []string{
		"foo@example.com",
		"foo@example",
		"foo+bar123@example.com",
		"f.o.o@example.com",
	}

	invalidCases := []string{
		"@example.com",
		"foo@",
	}

	for _, email := range validCases {
		if !emailRE.MatchString(email) {
			t.Errorf("emailRE.MatchString(%q) unexpectedly returned false", email)
		}
	}

	for _, email := range invalidCases {
		if emailRE.MatchString(email) {
			t.Errorf("emailRE.MatchString(%q) unexpectedly returned true", email)
		}
	}
}

func TestHostRE(t *testing.T) {
	validCases := []string{
		// Bare Hosts
		"example.com",
		"localhost",
		"127.0.0.1",

		// Hosts with Ports
		"example.com:8080",
		"127.0.0.1:8080",
		"localhost:8080",
	}

	invalidCases := []string{
		// Missing Host or Port
		"",
		":",
		":8080",
		"example.com:",

		// Nonsensical Values
		"example.com:80:80",

		// Invalid IPv6 literals
		"::1",
		"::1:8080",

		// IPv6 literals which are technically valid, but supporting them would
		// make the validation more complex than it's likely worth.
		"[::1]",
		"[::1]:8080",
	}

	for _, host := range validCases {
		if !hostRE.MatchString(host) {
			t.Errorf("hostRE.MatchString(%q) unexpectedly returned false", host)
		}
	}

	for _, host := range invalidCases {
		if hostRE.MatchString(host) {
			t.Errorf("hostRE.MatchString(%q) unexpectedly returned true", host)
		}
	}
}
