package middlewares

import (
	"authz-service/pkg/auth/jwt"
	"authz-service/pkg/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware creates a Gin middleware for JWT authentication with the default OpenID endpoint
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get OpenID config URL from application context
		openIDConfigURL, exists := c.MustGet("AzureOpenidConfigURL").(string)
		if !exists {
			logger.LogError("OpenID config URL not set")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "OpenID config URL not set"})
			return
		}

		// Create authenticator with default options but custom OpenID config URL
		options := jwt.DefaultOptions()
		options.OpenIDConfigURL = openIDConfigURL

		authenticator, err := jwt.NewAuthenticator(options)
		if err != nil {
			logger.LogError("Failed to initialize JWT authenticator", "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Failed to initialize authenticator"})
			return
		}

		// Use the JWT middleware
		authenticator.GinMiddleware()(c)
	}
}
