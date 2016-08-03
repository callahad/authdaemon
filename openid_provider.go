package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/square/go-jose"
)

// oidcAddRoutes adds OpenID Connect endpoints to an existing gin.IRouter.
func oidcAddRoutes(router gin.IRouter, origin string, rsakey *rsa.PrivateKey) {
	jwksPath := "/jwks.json"
	authPath := "/authorize"

	router.GET("/.well-known/openid-configuration", discovery(origin, jwksPath, authPath))
	router.GET(jwksPath, keyset(&rsakey.PublicKey))
	router.POST(authPath, authorize(origin, rsakey))
}

// -- HTTP Handlers ---

// discovery creates a handler for OpenID Connect Discovery 1.0 requests, as per
// the spec at http://openid.net/specs/openid-connect-discovery-1_0.html.
//
// The `form_post` response type is from the OAuth 2.0 Form Post Response Mode
// spec at http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html.
func discovery(origin string, jwksPath string, authPath string) func(*gin.Context) {
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
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
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
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	return func(c *gin.Context) {
		c.JSON(200, document)
	}
}

// keyset creates a handler that publishes the host's public keys as a JWK Set.
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

// authorize creates a handler for OpenID Connect authorization requests.
func authorize(origin string, key *rsa.PrivateKey) func(*gin.Context) {
	return func(c *gin.Context) {
		var form AuthRequest

		bindErr := c.Bind(&form)

		// Are any `binding:"required"` fields missing?
		if fieldsErr := form.complete(); fieldsErr != nil {
			fail(c, "Missing Field", fieldsErr.Error())
			return
		}

		// Are any field values invalid?
		if validErr := form.valid(); validErr != nil {
			fail(c, "Bad Value", validErr.Error())
			return
		}

		// Did something else go wrong?
		if bindErr != nil {
			fail(c, "Unknown Error", bindErr.Error())
			return
		}

		// TODO: If present, persist optional form.State and form.Nonce values.
		// State is returned as a query parameter outside of the JWT itself.
		// Nonce is returned as a member value of the JWT.

		// TODO: Trigger an appropriate authentication method
		c.String(500, "FIXME: Unimplemented")
	}
}

// --- TYPES ---

// AuthRequest represents an OpenID Connect / OAuth2 authorization request body.
type AuthRequest struct {
	// Required
	Scope        string `form:"scope" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`

	// NOTE: Technically optional, but handling omission is not yet implemented
	LoginHint string `form:"login_hint" binding:"required"`

	// Optional
	ResponseMode string `form:"response_mode"`
	State        string `form:"state"`
	Nonce        string `form:"nonce"`
}

// complete verifies that all required fields are present.
func (params *AuthRequest) complete() error {
	structure := reflect.TypeOf(*params)
	values := reflect.ValueOf(*params)
	for i := 0; i < structure.NumField(); i++ {
		field := structure.Field(i)
		required := field.Tag.Get("binding") == "required"
		name := field.Tag.Get("form")
		value := strings.TrimSpace(values.Field(i).String())

		if required && value == "" {
			return fmt.Errorf("No value for required field: %s", name)
		}
	}

	return nil
}

// valid verifies that all field values are valid.
func (params *AuthRequest) valid() error {
	urlNote := "Note: urls must be absolute, must use http or https, and must omit default ports"

	type testCase struct {
		description string
		ok          bool
	}

	// Array of validation testCases to check.
	tests := []testCase{
		// scope
		{
			"scope must be exactly 'openid email'",
			params.Scope == "openid email",
		},

		// response_type
		{
			"response_type must be exactly 'id_token'",
			params.ResponseType == "id_token",
		},

		// client_id (TODO: Validate against Origin or Referer headers?)
		{
			"client_id must be a valid url. " + urlNote,
			validURI(params.ClientID),
		},
		{
			"client_id must not include paths, query values, or fragments",
			onlyOrigin(params.ClientID),
		},

		// redirect_uri
		{
			"redirect_uri must be a valid url. " + urlNote,
			validURI(params.RedirectURI),
		},
		{
			"redirect_uri must be an absolute url that falls within client_id's origin",
			containedBy(params.RedirectURI, params.ClientID),
		},

		// response_mode
		{
			"response_mode must be 'params_post' or empty",
			params.ResponseMode == "params_post" || params.ResponseMode == "",
		},

		// login_hint (NOTE: This could be made optional in the future.)
		{
			"login_hint must look like a valid email address",
			emailRE.MatchString(params.LoginHint),
		},
	}

	for _, v := range tests {
		if !v.ok {
			return errors.New(v.description)
		}
	}

	return nil
}

// --- HELPERS ---

// generateKid deterministically generates a JWK Key ID by hashing a public key.
func generateKid(key *rsa.PublicKey) string {
	h := sha1.New()
	h.Write(key.N.Bytes())
	return fmt.Sprintf("%x", h.Sum(nil))
}

// fail sets the status code and response body for handling bad requests.
func fail(c *gin.Context, errType string, errMsg string) {
	c.JSON(400, gin.H{
		"error":   errType,
		"message": errMsg,
	})
}
