package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"authz-service/gql"
	"authz-service/middlewares"
	"authz-service/pkg/auth"
	"authz-service/pkg/logger"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/gin-gonic/gin"
	"github.com/permitio/permit-golang/pkg/config"
	"github.com/permitio/permit-golang/pkg/permit"
)

// Global permit service
var permitService *auth.PermitService

func main() {
	// Initialize logger
	logger.InitLogger()
	logger.LogInfo("Starting Authorization Service")

	// Initialize Permit.io client and service
	initPermitService()

	// Set Gin mode
	// gin.SetMode(gin.ReleaseMode)
	gin.SetMode(gin.DebugMode) // Using debug mode for development

	// Create a new Gin router with middlewares
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middlewares.RequestLogger()) // Use our custom logging middleware

	// Setup routes
	setupRoutes(router)

	// Create HTTP server
	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		logger.LogInfo("Server starting", "address", ":8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.LogFatal("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.LogInfo("Shutting down server...")

	// Create a deadline to wait for current operations to complete
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.LogFatal("Server forced to shutdown", "error", err)
	}

	logger.LogInfo("Server exited properly")
}

// Initialize the Permit.io client and service
func initPermitService() {
	// In production, get this from environment variables
	apiKey := os.Getenv("PERMIT_API_KEY")
	if apiKey == "" {
		apiKey = "[your-api-key]" // For development only, replace with your actual API key in production
	}

	// Configure Permit client
	permitConfig := config.NewConfigBuilder(apiKey).
		WithPdpUrl("https://cloudpdp.api.permit.io").
		Build()

	// Create permit client instance
	permitClient := permit.New(permitConfig)

	// Create permit service
	permitService = auth.NewPermitService(permitClient)

	logger.LogInfo("Permit.io service initialized")
}

// GraphQL middleware to pass user context from Gin to GraphQL resolvers
func graphqlUserContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from Gin context (set by auth middleware)
		//userID, exists := c.Get("userID")
		userID, exists := 123, true
		if exists {
			// Create a new context with the user ID
			ctx := context.WithValue(c.Request.Context(), "userID", userID)
			// Update the request with the new context
			c.Request = c.Request.WithContext(ctx)
		}
		c.Next()
	}
}

// Setup API routes
func setupRoutes(router *gin.Engine) {
	// Create GraphQL handler
	resolver := gql.NewResolver(permitService)
	graphqlHandler := handler.NewDefaultServer(gql.NewExecutableSchema(gql.Config{Resolvers: resolver}))

	// Root route - redirect to playground in development, or show a simple message in production
	router.GET("/", func(c *gin.Context) {
		if gin.Mode() != gin.ReleaseMode {
			c.Redirect(http.StatusFound, "/playground")
		} else {
			c.JSON(http.StatusOK, gin.H{
				"message": "Authorization Service API",
				"endpoints": []string{
					"/health - Health check endpoint",
					"/graphql - Protected GraphQL endpoint (requires auth)",
					"/graphql/public - Public GraphQL endpoint",
				},
			})
		}
	})

	// Health check route - no auth required
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// GraphQL playground - generally only enabled in development
	if gin.Mode() != gin.ReleaseMode {
		router.GET("/playground", func(c *gin.Context) {
			playground.Handler("GraphQL Playground", "/graphql").ServeHTTP(c.Writer, c.Request)
		})
	}

	// Public GraphQL endpoint - no auth required
	// Only allows introspection and health/version queries
	router.POST("/graphql/public", func(c *gin.Context) {
		graphqlHandler.ServeHTTP(c.Writer, c.Request)
	})

	// Protected GraphQL endpoint - require JWT auth
	protected := router.Group("/graphql")
	protected.Use(middlewares.AuthMiddleware(), graphqlUserContext())
	protected.POST("", func(c *gin.Context) {
		graphqlHandler.ServeHTTP(c.Writer, c.Request)
	})
}
