// Package config provides the configuration management for the application
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config represents the complete application configuration
type Config struct {
	Environment string
	Version     string
	Server      ServerConfig
	Logging     LoggingConfig
	Auth        AuthConfig
	Permit      PermitConfig
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string
	Format string
}

// AuthConfig contains authentication settings
type AuthConfig struct {
	OpenIDConfigURL   string
	UserClaimField    string
	JWKSCacheDuration time.Duration
}

// PermitConfig contains Permit.io settings
type PermitConfig struct {
	APIKey string
	PDPURL string
}

// Load loads configuration from .env file and environment variables
func Load() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		// Don't return error if .env file doesn't exist, just log a warning
		if !os.IsNotExist(err) {
			fmt.Printf("Warning: Error loading .env file: %v\n", err)
		}
	}

	// Set default values
	cfg := &Config{
		Environment: getEnv("ENVIRONMENT", "development"),
		Version:     getEnv("VERSION", "dev"),
		Server: ServerConfig{
			Port:         getEnvAsInt("PORT", 8080),
			ReadTimeout:  getEnvAsDuration("SERVER_READ_TIMEOUT", 5*time.Second),
			WriteTimeout: getEnvAsDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:  getEnvAsDuration("SERVER_IDLE_TIMEOUT", 120*time.Second),
		},
		Logging: LoggingConfig{
			Level:  getEnv("LOG_LEVEL", "info"),
			Format: getEnv("LOG_FORMAT", "json"),
		},
		Auth: AuthConfig{
			OpenIDConfigURL:   getEnv("OPENID_CONFIG_URL", ""),
			UserClaimField:    getEnv("JWT_USER_CLAIM_FIELD", "sub"),
			JWKSCacheDuration: getEnvAsDuration("JWKS_CACHE_DURATION", 30*time.Minute),
		},
		Permit: PermitConfig{
			APIKey: getEnv("PERMIT_API_KEY", ""),
			PDPURL: getEnv("PERMIT_PDP_URL", "https://cloudpdp.api.permit.io"),
		},
	}

	// If OpenID Config URL is not set, try to build it from Azure Tenant ID
	if cfg.Auth.OpenIDConfigURL == "" {
		tenantID := getEnv("AZURE_TENANT_ID", "")
		if tenantID != "" {
			cfg.Auth.OpenIDConfigURL = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", tenantID)
		} else {
			return nil, fmt.Errorf("either OPENID_CONFIG_URL or AZURE_TENANT_ID must be set")
		}
	}

	// Validate config
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validateConfig validates the configuration
func validateConfig(cfg *Config) error {
	// Required fields
	if cfg.Auth.OpenIDConfigURL == "" {
		return fmt.Errorf("OpenID configuration URL is required")
	}

	if cfg.Permit.APIKey == "" {
		return fmt.Errorf("Permit.io API key is required")
	}

	return nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvAsInt gets an environment variable as an integer or returns a default value
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

// getEnvAsDuration gets an environment variable as a duration or returns a default value
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}

	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}
