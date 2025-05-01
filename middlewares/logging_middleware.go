package middlewares

import (
	"authz-service/pkg/logger" // Updated import path
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestLogger logs incoming HTTP requests.
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate a unique request ID
		requestID := uuid.New().String()
		c.Set("request_id", requestID)

		// Record the start time
		start := time.Now()

		// Process the request
		c.Next()

		// After the request is processed, calculate the duration
		duration := time.Since(start).Milliseconds()

		// Collect other useful info (e.g., status code, user ID, IP address)
		statusCode := c.Writer.Status()
		userID := "" //c.Get("userID") // Optionally set user ID in the context
		ip := c.ClientIP()

		// Log the request
		logger.LogRequest(requestID, userID, ip, statusCode, duration, "Request Processed")
	}
}
