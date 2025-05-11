package auth

import (
	"authz-service/pkg/logger"
	"context"
	"errors"
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
func (s *PermitService) Check(ctx context.Context, userID, action, resourceType, resourceID, tenant string) (bool, error) {
	// Build user object for permission check
	user := enforcement.UserBuilder(userID).Build()

	// Build action object
	permitAction := enforcement.Action(action)

	// Build resource object for permission check
	resourceBuilder := enforcement.ResourceBuilder(resourceType)

	// Add tenant if provided
	if tenant != "" {
		resourceBuilder = resourceBuilder.WithTenant(tenant)
	}

	// Add resource ID if provided
	if resourceID != "" && resourceID != "*" {
		resourceBuilder = resourceBuilder.WithKey(resourceID)
	}

	resource := resourceBuilder.Build()

	// Perform permission check with Permit.io
	permitted, err := s.client.Check(user, permitAction, resource)
	if err != nil {
		logger.LogError("Permission check failed", "error", err, "user", userID, "action", action, "resource_type", resourceType, "resource_id", resourceID, "tenant", tenant)
		return false, err
	}

	if !permitted {
		err = errors.New("permission denied")
		logger.LogWarn("Permission denied", "user", userID, "action", action, "resource_type", resourceType, "resource_id", resourceID, "tenant", tenant)
		return false, err
	}
	logger.LogInfo("Permission check", "user", userID, "action", action, "resource_type", resourceType, "resource_id", resourceID, "tenant", tenant, "permitted", permitted)
	return permitted, nil
}

// PermissionRequest represents the JSON body for permission check requests
type PermissionRequest struct {
	Tenant     string `json:"tenant" binding:"required"`
	ResourceID string `json:"resourceId"`
}

// RequirePermission creates a middleware that checks if the user has permission
// to perform the given action on a resource of the given type.
func (s *PermitService) RequirePermission(action, resourceType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userID, exists := c.Get("userID")
		if !exists {
			logger.LogError("User ID not found in context during permission check")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
			c.Abort()
			return
		}

		// Parse request body to get tenant and resourceId
		var permReq PermissionRequest
		if err := c.ShouldBindJSON(&permReq); err != nil {
			// Try to get from query parameters if not in body
			tenant := c.Query("tenant")
			resourceID := c.Query("resourceId")

			if tenant == "" {
				logger.LogError("Missing tenant in request")
				c.JSON(http.StatusBadRequest, gin.H{"error": "Missing tenant in request"})
				c.Abort()
				return
			}

			permReq.Tenant = tenant
			permReq.ResourceID = resourceID
		}

		// Check permission
		allowed, err := s.Check(c.Request.Context(), userID.(string), action, resourceType, permReq.ResourceID, permReq.Tenant)
		if err != nil {
			logger.LogError("Failed to check permissions", "error", err, "tenant", permReq.Tenant)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permissions"})
			c.Abort()
			return
		}

		if !allowed {
			logger.LogWarn("Permission denied", "user", userID, "action", action, "resource_type", resourceType, "resource_id", permReq.ResourceID, "tenant", permReq.Tenant)
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			c.Abort()
			return
		}

		// Permission granted, proceed
		c.Next()
	}
}

// RequirePermissionWithParams creates a middleware that extracts parameters from URL
// This is an alternative to RequirePermission when the data is in URL params instead of body
func (s *PermitService) RequirePermissionWithParams(action, resourceType, resourceIDParam, tenantParam string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userID, exists := c.Get("userID")
		if !exists {
			logger.LogError("User ID not found in context during permission check")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
			c.Abort()
			return
		}

		// Get resource ID and tenant from path parameters
		resourceID := "*"
		if resourceIDParam != "" {
			resourceID = c.Param(resourceIDParam)
		}

		tenant := c.Param(tenantParam)
		if tenant == "" {
			tenant = c.Query("tenant")
		}
		if tenant == "" {
			logger.LogError("Missing tenant parameter")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing tenant parameter"})
			c.Abort()
			return
		}

		// Check permission
		allowed, err := s.Check(c.Request.Context(), userID.(string), action, resourceType, resourceID, tenant)
		if err != nil {
			logger.LogError("Failed to check permissions", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permissions"})
			c.Abort()
			return
		}

		if !allowed {
			logger.LogWarn("Permission denied", "user", userID, "action", action, "resource_type", resourceType, "resource_id", resourceID, "tenant", tenant)
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			c.Abort()
			return
		}

		// Permission granted, proceed
		c.Next()
	}
}
