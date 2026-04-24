// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package main — local type definitions for MockIssuer.
// These are intentionally inlined so the mock-issuer binary has zero
// dependencies on the Hydra module.

package main

import (
	"fmt"
	"time"
)

// ── Error types ───────────────────────────────────────────────────────────────

// OIDC4VCIError is an RFC-compliant OAuth 2.0 / OIDC4VCI error.
type OIDC4VCIError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	HTTPStatus  int    `json:"-"`
}

func (e *OIDC4VCIError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// newOIDCError creates an OIDC4VCIError.
func newOIDCError(code string, httpStatus int, description string) *OIDC4VCIError {
	return &OIDC4VCIError{Code: code, HTTPStatus: httpStatus, Description: description}
}

// Sentinel errors used by the store.
var (
	errNotFound     = newOIDCError("not_found", 404, "the requested resource was not found")
	errAlreadyExists = newOIDCError("already_exists", 409, "the resource already exists")
)

// Error code constants (OIDC4VCI spec).
const (
	errCodeInvalidToken          = "invalid_token"
	errCodeInvalidOrMissingProof = "invalid_or_missing_proof"
	errCodeUnsupportedCredType   = "unsupported_credential_type"
	errCodeServerError           = "server_error"
)

// defaultNonceTTL is the default nonce TTL in seconds (5 minutes).
const defaultNonceTTL = 300

// ── Data models ───────────────────────────────────────────────────────────────

// CredentialConfiguration describes a credential type the issuer can issue.
type CredentialConfiguration struct {
	ID                                  string                `json:"id"`
	Format                              string                `json:"format"`
	Scope                               string                `json:"scope,omitempty"`
	CryptographicBindingMethodsSupported []string             `json:"cryptographic_binding_methods_supported,omitempty"`
	CredentialSigningAlgValuesSupported  []string             `json:"credential_signing_alg_values_supported,omitempty"`
	ProofTypesSupported                 map[string]*ProofType `json:"proof_types_supported,omitempty"`
	Display                             []CredentialDisplay   `json:"display,omitempty"`
	VCT                                 string                `json:"vct,omitempty"`
	Doctype                             string                `json:"doctype,omitempty"`
	CredentialDefinition                *CredentialDefinition `json:"credential_definition,omitempty"`
	CreatedAt                           time.Time             `json:"-"`
	UpdatedAt                           time.Time             `json:"-"`
}

// ProofType describes proof signing algorithm support.
type ProofType struct {
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported,omitempty"`
}

// CredentialDisplay holds display metadata for a credential.
type CredentialDisplay struct {
	Name            string `json:"name"`
	Locale          string `json:"locale,omitempty"`
	Description     string `json:"description,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// CredentialDefinition defines the structure of a W3C VCDM credential.
type CredentialDefinition struct {
	Type              []string                    `json:"type"`
	CredentialSubject map[string]*ClaimDefinition `json:"credentialSubject,omitempty"`
}

// ClaimDefinition describes a single claim.
type ClaimDefinition struct {
	Mandatory bool   `json:"mandatory,omitempty"`
	ValueType string `json:"value_type,omitempty"`
}

// CredentialOffer represents a credential offer from the issuer to a wallet.
type CredentialOffer struct {
	ID                         string       `json:"id,omitempty"`
	CredentialIssuer           string       `json:"credential_issuer"`
	CredentialConfigurationIDs []string     `json:"credential_configuration_ids"`
	Grants                     *OfferGrants `json:"grants,omitempty"`
	CreatedAt                  time.Time    `json:"-"`
	ExpiresAt                  time.Time    `json:"-"`
}

// OfferGrants contains grant information for a credential offer.
type OfferGrants struct {
	AuthorizationCode *AuthorizationCodeGrant `json:"authorization_code,omitempty"`
	PreAuthorizedCode *PreAuthorizedCodeGrant `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

// AuthorizationCodeGrant contains parameters for the authorization code grant.
type AuthorizationCodeGrant struct {
	IssuerState string `json:"issuer_state,omitempty"`
}

// PreAuthorizedCodeGrant contains parameters for the pre-authorized code grant.
type PreAuthorizedCodeGrant struct {
	PreAuthorizedCode string  `json:"pre-authorized_code"`
	TxCode            *TxCode `json:"tx_code,omitempty"`
}

// TxCode describes transaction code (PIN) requirements.
type TxCode struct {
	Value       string `json:"value,omitempty"`
	InputMode   string `json:"input_mode,omitempty"`
	Length      int    `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
}

// Nonce represents a single-use proof-of-possession nonce.
type Nonce struct {
	Value     string
	ExpiresAt time.Time
}

// IssuanceRecord records a credential issuance event.
type IssuanceRecord struct {
	ID                        string
	Subject                   string
	CredentialConfigurationID string
	CredentialIdentifier      string
	IssuedAt                  time.Time
	ExpiresAt                 *time.Time
	Revoked                   bool
	RevokedAt                 *time.Time
}

// IssuanceFilters filters for listing issuance records.
type IssuanceFilters struct {
	Subject                   string
	CredentialConfigurationID string
	Revoked                   *bool
	Limit                     int
	Offset                    int
}

// DeferredCredential represents an asynchronously issued credential.
type DeferredCredential struct {
	TransactionID             string
	CredentialConfigurationID string
	Subject                   string
	Status                    string
	Credential                interface{}
	CreatedAt                 time.Time
	ExpiresAt                 time.Time
}
