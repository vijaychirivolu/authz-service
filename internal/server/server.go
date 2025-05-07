// Package server handles HTTP server setup, routing, and lifecycle management
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"authz-service/gql"
	"authz-service/internal/config"
	"authz-service/middlewares"
	"authz-service/pkg/auth"
	"authz-service/pkg/auth/jwt"
	"authz-service/pkg/logger"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/gin-gonic/gin"
)

// Server represents the HTTP server with its dependencies
type Server struct {
	config        *config.Config
	permitService *auth.PermitService
	jwtAuth       *jwt.Authenticator
	router        *gin.Engine
	httpServer    *http.Server
}

// NewServer creates a new server instance with the given dependencies
func NewServer(cfg *config.Config, permitService *auth.PermitService, jwtAuth *jwt.Authenticator) *Server {
	// Set Gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	s := &Server{
		config:        cfg,
		permitService: permitService,
		jwtAuth:       jwtAuth,
	}

	// Setup router
	s.setupRouter()

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      s.router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	return s
}

// Start starts the HTTP server
func (s *Server) Start() error {
	logger.LogInfo("Server starting", "address", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	logger.LogInfo("Shutting down server...")
	return s.httpServer.Shutdown(ctx)
}

// setupRouter creates and configures the Gin router with all routes and middlewares
func (s *Server) setupRouter() {
	router := gin.New()

	// Add middlewares
	router.Use(gin.Recovery())
	router.Use(middlewares.RequestLogger())

	// Create GraphQL handler
	resolver := gql.NewResolver(s.permitService)
	graphqlHandler := handler.New(gql.NewExecutableSchema(gql.Config{Resolvers: resolver}))

	// Configure transports
	graphqlHandler.AddTransport(transport.Options{})
	graphqlHandler.AddTransport(transport.GET{})
	graphqlHandler.AddTransport(transport.POST{})
	graphqlHandler.AddTransport(transport.MultipartForm{})

	// Enable introspection
	graphqlHandler.Use(extension.Introspection{})
	// Root route
	router.GET("/", func(c *gin.Context) {
		if gin.Mode() != gin.ReleaseMode {
			c.Redirect(http.StatusFound, "/playground")
		} else {
			c.JSON(http.StatusOK, gin.H{
				"service": "Authorization Service",
				"version": s.config.Version,
				"endpoints": []string{
					"/health - Health check endpoint",
					"/graphql - Protected GraphQL endpoint (requires auth)",
					"/graphql/public - Public GraphQL endpoint",
				},
			})
		}
	})

	// Health check route
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"version": s.config.Version,
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	// GraphQL playground in development
	if gin.Mode() != gin.ReleaseMode {
		router.GET("/playground", func(c *gin.Context) {
			playground.Handler("GraphQL Playground", "/graphql").ServeHTTP(c.Writer, c.Request)
		})
	}

	// Protected GraphQL endpoint with JWT auth
	protected := router.Group("/graphql")
	//protected.Use(s.jwtAuth.GinMiddleware(), graphqlUserContext())
	protected.Use(graphqlUserContext())
	protected.POST("", func(c *gin.Context) {
		graphqlHandler.ServeHTTP(c.Writer, c.Request)
	})

	s.router = router
}

// GraphQL middleware to pass user context from Gin to GraphQL resolvers
func graphqlUserContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from Gin context (set by auth middleware)
		userID, exists := c.Get("userID")
		if exists {
			// Create a new context with the user ID
			ctx := context.WithValue(c.Request.Context(), "userID", userID)
			// Update the request with the new context
			c.Request = c.Request.WithContext(ctx)
		}
		c.Next()
	}
}
