package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"authz-service/internal/app"
	"authz-service/pkg/logger"
)

func main() {
	// Initialize application
	application, err := app.Initialize()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	// Start server in a goroutine
	go func() {
		if err := application.Server.Start(); err != nil {
			logger.LogFatal("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Create a deadline to wait for current operations to complete
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := application.Server.Shutdown(ctx); err != nil {
		logger.LogFatal("Server forced to shutdown", "error", err)
	}

	logger.LogInfo("Server exited properly")
}
