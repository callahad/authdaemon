package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/square/go-jose"
)

func oidcAddRoutes(router *gin.Engine, origin string, rsakey *rsa.PrivateKey) {
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

	    Values to look at:
	        scope           must be "openid"
	        response_type   must be "id_token"
	        client_id       must be a valid origin and match Origin header (if sent)
	        redirect_uri    must be a valid URI within the client_id's origin
	        response_mode   optional, fail if present and not "form_post"
	        login_hint      optional, valid email address, for now, fail if omitted

	    Values to pass through:
	        state           optional string, returned outside of the JWT
	        nonce           optional string, returned inside of the JWT

	    If everything validates, select the first capable provider and begin auth.
	*/

	return func(c *gin.Context) {
		var form AuthRequest

		if err := c.Bind(&form); err != nil {
			panic(err)
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

// --- HELPERS ---

func generateKid(key *rsa.PublicKey) string {
	h := sha1.New()
	h.Write(key.N.Bytes())
	return fmt.Sprintf("%x", h.Sum(nil))
}
