package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/square/go-jose"
	"os"
)

const (
	VERSION = "0.1.0"
	REPO    = "https://github.com/callahad/authdaemon"
)

var (
	CONFIGURATION = struct {
		origin  string
		address string
		port    uint16
		key     rsa.PrivateKey
	}{
		origin:  "laoidc.herokuapp.com",
		address: "0.0.0.0",
		port:    3333,
		key: (func() rsa.PrivateKey {
			if key, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
				panic(err)
			}

			return *key
		})(),
	}

	SUPPORT_DOCUMENT = struct {
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
		Issuer:                           "https://" + CONFIGURATION.origin,
		AuthorizationEndpoint:            "https://" + CONFIGURATION.origin + "/auth",
		JwksURI:                          "https://" + CONFIGURATION.origin + "/jwks.json",
		ScopesSupported:                  []string{"openid", "email"},
		ClaimsSupported:                  []string{"aud", "email", "email_verified", "exp", "iat", "iss", "sub"},
		ResponseTypesSupported:           []string{"id_token"},
		ResponseModesSupported:           []string{"form_post"},
		GrantTypesSupports:               []string{"implicit"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
	}
)

func main() {
	router := gin.Default()

	// -- Website Routes
	router.GET("/", index)

	// -- OpenID Connect Provider API
	router.GET("/.well-known/openid-configuration", oidcDiscoveryDoc)
	router.GET("/jwks.json", oidcKeyset)
	router.POST("/authorize", oidcAuthorize)

	// Let the PORT environment variable override the configuration.
	// This is necessary for tools like https://github.com/codegangsta/gin
	port := os.Getenv("PORT")
	if len(port) <= 0 {
		port = fmt.Sprintf("%d", CONFIGURATION.port)
	}

	router.Run(fmt.Sprintf("%s:%s", CONFIGURATION.address, port))
}

func index(c *gin.Context) {
	c.String(200, "Hello, World!")
}

func oidcDiscoveryDoc(c *gin.Context) {
	c.JSON(200, SUPPORT_DOCUMENT)
}

func oidcKeyset(c *gin.Context) {
	// Hash the public key to generate a Key ID value
	key := CONFIGURATION.key.PublicKey
	data := key.N.Bytes()
	h := sha1.New()
	h.Write(data)
	kid := fmt.Sprintf("%x", h.Sum(nil))

	type jwkSet struct {
		Keys []jose.JsonWebKey `json:"keys"`
	}

	c.JSON(200, jwkSet{
		Keys: []jose.JsonWebKey{
			jose.JsonWebKey{
				Key:       &key,
				KeyID:     kid,
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	})
}

func oidcAuthorize(c *gin.Context) {
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

	c.String(500, "TODO: IMPLEMENT ME")
}
