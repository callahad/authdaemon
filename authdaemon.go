package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/gin-gonic/gin"
	"os"
)

const (
	VERSION        = "0.1.0"
	REPO           = "https://github.com/callahad/authdaemon"
	ORIGIN         = "laoidc.herokuapp.com"
	ADDRESS        = "0.0.0.0"
	PORT    uint16 = 3333
)

func main() {
	// TODO: Set up a config parser
	// Let the PORT environment variable override the configuration.
	// This is necessary for tools like https://github.com/codegangsta/gin
	// (Not to be confused with gin-gonic/gin, the web framework this uses.)
	port := os.Getenv("PORT")
	if len(port) <= 0 {
		port = fmt.Sprintf("%d", PORT)
	}

	// Generate an ephemeral RSA key for this instance
	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Set up routes and start server

	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.String(200, "Hello, World!")
	})

	oidcAddRoutes(router, ORIGIN, rsakey)

	router.Run(fmt.Sprintf("%s:%s", ADDRESS, port))
}
