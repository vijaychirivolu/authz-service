package auth

import (
	"authz-service/pkg/logger"
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/permitio/permit-golang/pkg/enforcement"
	"github.com/permitio/permit-golang/pkg/permit"
)

// PermitService provides authorization functionality using Permit.io
type PermitService struct {
	client *permit.Client
}

// NewPermitService creates a new PermitService instance
func NewPermitService(permitClient *permit.Client) *PermitService {
	return &PermitService{
		client: permitClient,
	}
}

// Check verifies if a user has permission to perform an action on a resource
func (s *PermitService) Check(ctx context.Context, userID, action, resourceType, resourceID string) (bool, error) {
	// Build user object for permission check
	user := enforcement.UserBuilder(userID).Build()

	// Build action object
	permitAction := enforcement.Action(action)

	// Build resource object for permission check
	// Note: ResourceBuilder takes the resource TYPE, not the ID
	resource := enforcement.ResourceBuilder(resourceType).Build()

	// The resource ID would typically be set in attributes or tenant
	// This may need to be adjusted based on your specific Permit.io setup

	// Perform permission check with Permit.io
	permitted, err := s.client.Check(user, permitAction, resource)
	if err != nil {
		logger.LogError("Permission check failed", "error", err, "user", userID, "action", action, "resource", resourceID)
		return false, err
	}

	logger.LogInfo("Permission check", "user", userID, "action", action, "resource", resourceType, "resource_id", resourceID, "permitted", permitted)
	return permitted, nil
}

// RequirePermission creates a middleware that checks if the user has permission
// to perform the given action on a resource of the given type.
// For resource ID, it uses the parameter with the given name from the URL.
func (s *PermitService) RequirePermission(action, resourceType, resourceIDParam string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userID, exists := c.Get("userID")
		if !exists {
			logger.LogError("User ID not found in context during permission check")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
			c.Abort()
			return
		}

		// Get resource ID from path or default to "*" if not specified
		resourceID := "*" // Default to all resources of this type
		if resourceIDParam != "" {
			resourceID = c.Param(resourceIDParam)
		}

		// Check permission
		allowed, err := s.Check(c.Request.Context(), userID.(string), action, resourceType, resourceID)
		if err != nil {
			logger.LogError("Failed to check permissions", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permissions"})
			c.Abort()
			return
		}

		if !allowed {
			logger.LogWarn("Permission denied", "user", userID, "action", action, "resource_type", resourceType, "resource_id", resourceID)
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			c.Abort()
			return
		}

		// Permission granted, proceed
		c.Next()
	}
}
