package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/square/go-jose"
	"net/url"
	"reflect"
	"regexp"
	"strings"
)

func oidcAddRoutes(router gin.IRouter, origin string, rsakey *rsa.PrivateKey) {
	jwksPath := "/jwks.json"
	authPath := "/authorize"

	router.GET("/.well-known/openid-configuration", discovery(origin, jwksPath, authPath))
	router.GET(jwksPath, keyset(&rsakey.PublicKey))
	router.POST(authPath, authorize(origin, rsakey))
}

// -- HTTP Handlers ---

func discovery(origin string, jwksPath string, authPath string) func(*gin.Context) {
	// Build an OpenID Connect Discovery 1.0 document compliant with:
	// http://openid.net/specs/openid-connect-discovery-1_0.html
	//
	// Note: The "form_post" response type is from this extension spec:
	// http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
	var document = struct {
		Issuer                           string   `json:"issuer"`
		AuthorizationEndpoint            string   `json:"authorization_endpoint"`
		JwksURI                          string   `json:"jwks_uri"`
		ScopesSupported                  []string `json:"scopes_supported"`
		ClaimsSupported                  []string `json:"claims_supported"`
		ResponseTypesSupported           []string `json:"response_types_supported"`
		ResponseModesSupported           []string `json:"response_modes_supported"`
		GrantTypesSupports               []string `json:"grant_types_supports"`
		SubjectTypesSupported            []string `json:"subject_types_supported"`
		IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	}{
		Issuer:                           "https://" + origin,
		AuthorizationEndpoint:            "https://" + origin + authPath,
		JwksURI:                          "https://" + origin + jwksPath,
		ScopesSupported:                  []string{"openid", "email"},
		ClaimsSupported:                  []string{"aud", "email", "email_verified", "exp", "iat", "iss", "sub"},
		ResponseTypesSupported:           []string{"id_token"},
		ResponseModesSupported:           []string{"form_post"},
		GrantTypesSupports:               []string{"implicit"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	return func(c *gin.Context) {
		c.JSON(200, document)
	}
}

func keyset(pubkey *rsa.PublicKey) func(*gin.Context) {
	jwkSet := jose.JsonWebKeySet{
		Keys: []jose.JsonWebKey{
			jose.JsonWebKey{
				Key:       pubkey,
				KeyID:     generateKid(pubkey),
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}

	return func(c *gin.Context) {
		c.JSON(200, jwkSet)
	}
}

func authorize(origin string, key *rsa.PrivateKey) func(*gin.Context) {
	/* TODO: Accept an OpenID Connect authorization request, validate it, and
		trigger an appropriate auth method.

		TODO: Values to pass through:
	        state           optional string, returned outside of the JWT
	        nonce           optional string, returned inside of the JWT
	*/

	return func(c *gin.Context) {
		var form AuthRequest

		bindErr := c.Bind(&form)

		// Look at every required field in the AuthRequest. If any are missing,
		// fail early and return a human-friendly error message.
		structure := reflect.TypeOf(form)
		values := reflect.ValueOf(form)
		for i := 0; i < structure.NumField(); i++ {
			field := structure.Field(i)
			required := field.Tag.Get("binding") == "required"
			name := field.Tag.Get("form")
			value := strings.TrimSpace(values.Field(i).String())

			if required && value == "" {
				fail(c, "Missing Field", fmt.Sprintf("No value for: %s", name))
				return
			}
		}

		if validErr := form.valid(); validErr != nil {
			fail(c, "Bad Value", validErr.Error())
			return
		}

		// Did something else go wrong?
		if bindErr != nil {
			fail(c, "Unknown Error", bindErr.Error())
			return
		}

		c.String(500, "FIXME: Unimplemented")
	}
}

// --- TYPES ---

type AuthRequest struct {
	// Required
	Scope        string `form:"scope" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
	ClientId     string `form:"client_id" binding:"required"`
	RedirectUri  string `form:"redirect_uri" binding:"required"`

	// TODO: Technically optional, but handling omission is not yet implemented
	LoginHint string `form:"login_hint" binding:"required"`

	// Optional
	ResponseMode string `form:"response_mode"`
	State        string `form:"state"`
	Nonce        string `form:"nonce"`
}

func (params *AuthRequest) valid() error {
	urlNote := "Note: urls must be absolute, use http or https, and must omit default ports"

	tests := []testCase{
		// scope
		{
			params.Scope == "openid email",
			"scope must be exactly 'openid email'",
		},

		// response_type
		{
			params.ResponseType == "id_token",
			"response_type must be exactly 'id_token'",
		},

		// client_id (TODO: Validate against Origin or Referer headers?)
		{
			validUri(params.ClientId),
			"client_id must be a valid url. " + urlNote,
		},
		{
			onlyOrigin(params.ClientId),
			"client_id must not include paths, query values, or fragments",
		},

		// redirect_uri
		{
			validUri(params.RedirectUri),
			"redirect_uri must be a valid url. " + urlNote,
		},
		{
			containedBy(params.RedirectUri, params.ClientId),
			"redirect_uri must be an absolute url that falls within client_id's origin",
		},

		// response_mode
		{
			params.ResponseMode == "params_post" || params.ResponseMode == "",
			"The only supported response_mode is 'params_post'",
		},

		// login_hint (TODO Make optional)
		{
			validEmail(params.LoginHint),
			"login_hint does not look like an email address",
		},
	}

	for _, v := range tests {
		if !v.pass {
			return errors.New(v.description)
		}
	}

	return nil
}

type testCase struct {
	pass        bool
	description string
}

// --- HELPERS ---

func generateKid(key *rsa.PublicKey) string {
	h := sha1.New()
	h.Write(key.N.Bytes())
	return fmt.Sprintf("%x", h.Sum(nil))
}

func fail(c *gin.Context, what string, msg string) {
	// TODO: There must be a better way to accmplish this...
	c.JSON(400, gin.H{
		"error":   what,
		"message": msg,
	})
}

// Validating email addresses with regexes is of questionable value, and this
// pattern may exclude some legitimate addresses. Suggestions welcome.
var emailRE = regexp.MustCompile(`^[a-zA-Z0-9][+-_.a-zA-Z0-9]*@[-_.a-zA-Z0-9]+$`)

func validEmail(addr string) bool {
	return emailRE.MatchString(addr)
}

func validUri(uri string) bool {
	u, err := url.Parse(uri)

	tests := []bool{
		// URL must parse
		err == nil,

		// Must be either HTTP or HTTPS and omit default ports
		u.Scheme == "http" || u.Scheme == "https",
		!(u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")),
		!(u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")),

		// Must not have opaque data
		u.Opaque == "",

		// Must not have a user:password prefix
		u.User == nil,
	}

	for _, test := range tests {
		if !test {
			return false
		}
	}

	return true
}

func onlyOrigin(uri string) bool {
	u, err := url.Parse(uri)

	if err != nil || !validUri(uri) || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}

	return true
}

func containedBy(url string, origin string) bool {
	if !validUri(origin) || !validUri(url) {
		return false
	}

	if !onlyOrigin(origin) {
		return false
	}

	return strings.HasPrefix(url, origin)
}
