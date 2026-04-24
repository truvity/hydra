// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for the MockIssuer standalone service.
// MockIssuer emulates an OIDC4VCI Credential Issuer for E2E testing.
// It uses in-memory storage and delegates token validation to Hydra's
// admin introspection endpoint.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := LoadConfig()

	// Generate ECDSA P-256 signing key
	signer, err := NewSigner()
	if err != nil {
		log.Fatalf("failed to generate signing key: %v", err)
	}
	log.Printf("signing key generated (kid=%s)", signer.KeyID())

	// Initialise in-memory store
	store := NewMemoryStore()

	// Initialise nonce manager
	nonces := NewNonceManager(store, cfg.NonceTTL)

	// Build HTTP handler (registers all routes)
	handler := NewHandler(cfg, store, nonces, signer)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in background
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("MockIssuer listening on %s (issuer_url=%s)", cfg.ListenAddr, cfg.IssuerURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Wait for shutdown signal or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Printf("received signal %s, shutting down…", sig)
	case err := <-serverErr:
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}

	// Graceful shutdown with 5-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
		os.Exit(1)
	}
	log.Println("MockIssuer stopped")
}
