package gql

import (
	"authz-service/pkg/auth"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	permitService *auth.PermitService
	version       string
}

// NewResolver creates a new resolver with dependencies
func NewResolver(permitService *auth.PermitService) *Resolver {
	return &Resolver{
		permitService: permitService,
		version:       "1.0.0",
	}
}
