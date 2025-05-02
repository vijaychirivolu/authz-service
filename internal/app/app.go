// Package app manages application lifecycle and dependency initialization
package app

import (
	"authz-service/internal/config"
	"authz-service/internal/server"
	"authz-service/pkg/auth"
	"authz-service/pkg/auth/jwt"
	"authz-service/pkg/logger"
	"fmt"

	permitcfg "github.com/permitio/permit-golang/pkg/config"
	"github.com/permitio/permit-golang/pkg/permit"
)

// Application represents the main application with all its dependencies
type Application struct {
	Config        *config.Config
	PermitService *auth.PermitService
	JWTAuth       *jwt.Authenticator
	Server        *server.Server
}

// Initialize sets up the application and all its dependencies
func Initialize() (*Application, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize logger
	logger.InitLogger(logger.LogConfig{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
	})
	logger.LogInfo("Starting Authorization Service", "version", cfg.Version)

	// Initialize Permit.io service
	permitService, err := initPermitService(cfg.Permit)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Permit.io service: %w", err)
	}

	// Initialize JWT authenticator
	jwtAuth, err := initJWTAuthenticator(cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWT authenticator: %w", err)
	}

	// Create server
	srv := server.NewServer(cfg, permitService, jwtAuth)

	return &Application{
		Config:        cfg,
		PermitService: permitService,
		JWTAuth:       jwtAuth,
		Server:        srv,
	}, nil
}

// Initialize the Permit.io client and service
func initPermitService(cfg config.PermitConfig) (*auth.PermitService, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("Permit.io API key is not set")
	}

	// Configure Permit client
	permitConfig := permitcfg.NewConfigBuilder(cfg.APIKey).
		WithPdpUrl(cfg.PDPURL).
		Build()

	// Create permit client instance
	permitClient := permit.New(permitConfig)

	// Create permit service
	service := auth.NewPermitService(permitClient)
	logger.LogInfo("Permit.io service initialized")

	return service, nil
}

// Initialize the JWT authenticator
func initJWTAuthenticator(cfg config.AuthConfig) (*jwt.Authenticator, error) {
	// Configure JWT authenticator
	options := jwt.DefaultOptions()
	options.OpenIDConfigURL = cfg.OpenIDConfigURL
	options.UserClaimField = cfg.UserClaimField
	options.CacheDuration = cfg.JWKSCacheDuration

	jwtAuth, err := jwt.NewAuthenticator(options)
	if err != nil {
		return nil, err
	}

	logger.LogInfo("JWT authenticator initialized", "openIDConfigURL", cfg.OpenIDConfigURL)
	return jwtAuth, nil
}
