package middlewares

import (
	"authz-service/pkg/logger"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// JWTClaims structure for Entra JWT tokens
type JWTClaims struct {
	// Standard claims
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`

	// Microsoft Entra ID specific claims
	OID               string   `json:"oid"`                // Object ID (primary user identifier)
	PreferredUsername string   `json:"preferred_username"` // User's email or username
	Name              string   `json:"name"`               // User's full name
	Roles             []string `json:"roles"`              // User roles (if included in token)
	Groups            []string `json:"groups"`             // User groups (if included in token)
	TID               string   `json:"tid"`                // Tenant ID
}

// DecodeToken decodes a JWT token without validation (similar to jwt.io)
func DecodeToken(tokenString string) (*JWTClaims, error) {
	// Remove "Bearer " prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	// Split the token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		logger.LogError("Invalid token format")
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode the claims part (second part)
	claimsPart, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		logger.LogError("Failed to decode claims", "error", err)
		return nil, fmt.Errorf("failed to decode claims: %v", err)
	}

	// Parse the claims
	var claims JWTClaims
	if err := json.Unmarshal(claimsPart, &claims); err != nil {
		logger.LogError("Failed to parse claims", "error", err)
		return nil, fmt.Errorf("failed to parse claims: %v", err)
	}

	// Check if token is expired
	if claims.Exp > 0 && time.Unix(claims.Exp, 0).Before(time.Now()) {
		logger.LogError("Token is expired")
		return nil, fmt.Errorf("token is expired")
	}

	return &claims, nil
}

// AuthMiddleware validates JWT in the Authorization header
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the token from the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.LogError("Authorization header missing")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			c.Abort()
			return
		}

		// Check if the token is prefixed with "Bearer"
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			logger.LogError("Bearer token missing")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token missing"})
			c.Abort()
			return
		}

		// Decode token without validation (for demo purposes)
		// In production, you should use a proper JWT validation library
		decodedClaims, err := DecodeToken(authHeader)
		if err != nil {
			logger.LogError("Failed to decode token", "error", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Invalid token: %v", err)})
			c.Abort()
			return
		}

		// Use OID (Object ID) as the primary user identifier for Entra ID
		userID := decodedClaims.OID
		// if userID == "" {
		// 	// Fall back to sub claim if OID is not present
		// 	userID = decodedClaims.Sub
		// 	if userID == "" {
		// 		logger.LogError("User ID not found in token")
		// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		// 		c.Abort()
		// 		return
		// 	}
		// }

		// Set user information in the context
		c.Set("userID", 123)

		// Optionally set additional claims for use in handlers
		c.Set("username", decodedClaims.PreferredUsername)
		c.Set("name", decodedClaims.Name)
		c.Set("userRoles", decodedClaims.Roles)
		c.Set("userGroups", decodedClaims.Groups)
		c.Set("tenantID", decodedClaims.TID)

		logger.LogInfo("JWT token decoded successfully",
			"user_id", userID,
			"username", decodedClaims.PreferredUsername,
			"tenant", decodedClaims.TID)

		c.Next()
	}
}
