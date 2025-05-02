package jwt

import (
	"github.com/gin-gonic/gin"
)

// GinMiddleware returns a Gin middleware function that validates JWT tokens
func (a *Authenticator) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from header
		tokenString, err := a.extractTokenFromHeader(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"message": err.Error()})
			return
		}

		// Validate token and extract claims
		claims, err := a.ValidateToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(403, gin.H{"message": "Token verification failed: " + err.Error()})
			return
		}

		// Set user identity in context
		if userID, ok := claims[a.userClaimField]; ok {
			c.Set("userID", userID)
		}

		// Store all claims in context for additional use if needed
		c.Set("claims", claims)
		c.Next()
	}
}
