// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Handler wires together all MockIssuer components and registers HTTP routes.
type Handler struct {
	cfg      *Config
	store    *MemoryStore
	nonces   *NonceManager
	signer   *Signer
	metadata *MetadataProvider
	tv       *TokenValidator
	mux      *http.ServeMux
}

// NewHandler creates a Handler and registers all routes on a new ServeMux.
func NewHandler(cfg *Config, store *MemoryStore, nonces *NonceManager, signer *Signer) *Handler {
	h := &Handler{
		cfg:      cfg,
		store:    store,
		nonces:   nonces,
		signer:   signer,
		metadata: NewMetadataProvider(cfg, store),
		tv:       NewTokenValidator(cfg.AuthServerAdminURL),
		mux:      http.NewServeMux(),
	}
	h.registerRoutes()
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) registerRoutes() {
	// Public endpoints
	h.mux.HandleFunc("GET /.well-known/openid-credential-issuer", h.handleMetadata)
	h.mux.HandleFunc("POST /nonce", h.handleNonce)
	h.mux.HandleFunc("POST /credential", h.handleCredential)

	// Admin – credential configurations
	h.mux.HandleFunc("POST /admin/oidc4vci/credential-configurations", h.handleCreateCredentialConfig)
	h.mux.HandleFunc("GET /admin/oidc4vci/credential-configurations", h.handleListCredentialConfigs)
	h.mux.HandleFunc("GET /admin/oidc4vci/credential-configurations/", h.handleGetOrUpdateOrDeleteCredentialConfig)
	h.mux.HandleFunc("PUT /admin/oidc4vci/credential-configurations/", h.handleGetOrUpdateOrDeleteCredentialConfig)
	h.mux.HandleFunc("DELETE /admin/oidc4vci/credential-configurations/", h.handleGetOrUpdateOrDeleteCredentialConfig)

	// Admin – credential offers
	h.mux.HandleFunc("POST /admin/oidc4vci/credential-offers", h.handleCreateCredentialOffer)
	h.mux.HandleFunc("GET /admin/oidc4vci/credential-offers", h.handleListCredentialOffers)
	h.mux.HandleFunc("GET /admin/oidc4vci/credential-offers/", h.handleGetOrDeleteCredentialOffer)
	h.mux.HandleFunc("DELETE /admin/oidc4vci/credential-offers/", h.handleGetOrDeleteCredentialOffer)
}

// ── Public: metadata ──────────────────────────────────────────────────────────

func (h *Handler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	meta, err := h.metadata.Build(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, meta)
}

// ── Public: nonce ─────────────────────────────────────────────────────────────

func (h *Handler) handleNonce(w http.ResponseWriter, r *http.Request) {
	nonce, err := h.nonces.GenerateNonce(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, errCodeServerError, "failed to generate nonce")
		return
	}
	// OIDC4VCI §7.2: the nonce response MUST NOT be cached.
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"c_nonce":            nonce.Value,
		"c_nonce_expires_in": h.nonces.TTLSeconds(),
	})
}

// ── Public: credential issuance ───────────────────────────────────────────────

type credentialRequest struct {
	// credential_configuration_id and credential_identifier are mutually
	// exclusive per OIDC4VCI §8.2. Wallets that went through an
	// authorization_details flow send credential_identifier (from the
	// credential_identifiers array in the token response); wallets using a
	// scope-only flow send credential_configuration_id.
	CredentialConfigurationID string                 `json:"credential_configuration_id"`
	CredentialIdentifier      string                 `json:"credential_identifier"`
	Format                    string                 `json:"format"`
	Proofs                    map[string]interface{} `json:"proofs"`
}

type credentialResponse struct {
	Credentials     []map[string]interface{} `json:"credentials"`
	CNonce          string                   `json:"c_nonce"`
	CNonceExpiresIn int                      `json:"c_nonce_expires_in"`
}

func (h *Handler) handleCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Extract access token + accepted scheme (Bearer or DPoP).
	scheme, token, err := extractAuthzHeader(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, errCodeInvalidToken, err.Error())
		return
	}
	switch scheme {
	case "bearer", "dpop":
		// accepted
	default:
		h.writeError(w, http.StatusUnauthorized, errCodeInvalidToken,
			fmt.Sprintf("unsupported Authorization scheme %q (expected Bearer or DPoP)", scheme))
		return
	}

	// 2. Introspect the token via Hydra.
	tokenInfo, err := h.tv.Validate(ctx, token)
	if err != nil {
		var oidcErr *OIDC4VCIError
		if errors.As(err, &oidcErr) {
			h.writeError(w, oidcErr.HTTPStatus, oidcErr.Code, oidcErr.Description)
		} else {
			h.writeError(w, http.StatusUnauthorized, errCodeInvalidToken, err.Error())
		}
		return
	}

	// 3. DPoP proof-of-possession (RFC 9449 §7). If the introspection result
	// carries a cnf.jkt claim, the token is sender-constrained and a DPoP
	// proof matching that thumbprint must be present on the request.
	jkt, tokenIsDPoP := extractCnfJKT(tokenInfo.Extra)
	if tokenIsDPoP || scheme == "dpop" {
		if scheme != "dpop" {
			h.writeError(w, http.StatusUnauthorized, errCodeInvalidToken,
				"access token is DPoP-bound but request used Bearer scheme")
			return
		}
		if err := validateDPoPProof(r, token, jkt); err != nil {
			var oidcErr *OIDC4VCIError
			if errors.As(err, &oidcErr) {
				h.writeError(w, oidcErr.HTTPStatus, oidcErr.Code, oidcErr.Description)
			} else {
				h.writeError(w, http.StatusUnauthorized, errCodeInvalidToken, err.Error())
			}
			return
		}
	}

	// 2. Parse request body
	var req credentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}

	// 3. Resolve the requested credential configuration. Per OIDC4VCI §8.2
	// the wallet uses either credential_identifier (from the token response)
	// or credential_configuration_id — never both.
	switch {
	case req.CredentialIdentifier != "" && req.CredentialConfigurationID != "":
		h.writeError(w, http.StatusBadRequest, "invalid_request",
			"credential_identifier and credential_configuration_id are mutually exclusive")
		return
	case req.CredentialIdentifier == "" && req.CredentialConfigurationID == "":
		h.writeError(w, http.StatusBadRequest, errCodeUnsupportedCredType,
			"credential_identifier or credential_configuration_id is required")
		return
	}

	configID := req.CredentialConfigurationID
	if req.CredentialIdentifier != "" {
		// The wallet presented a credential_identifier — it MUST appear in
		// authorization_details.credential_identifiers on the access token
		// (OIDC4VCI §8.2). Map it back to the owning credential_configuration_id.
		found, resolvedID, err := resolveCredentialIdentifier(
			tokenInfo.Extra, req.CredentialIdentifier)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, errCodeUnsupportedCredType, err.Error())
			return
		}
		if !found {
			h.writeError(w, http.StatusBadRequest, errCodeUnsupportedCredType,
				fmt.Sprintf("credential_identifier %q is not authorized by the access token",
					req.CredentialIdentifier))
			return
		}
		configID = resolvedID
	}

	cfg, err := h.store.GetCredentialConfiguration(ctx, configID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			h.writeError(w, http.StatusBadRequest, errCodeUnsupportedCredType,
				fmt.Sprintf("credential configuration %q not found", configID))
			return
		}
		h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
		return
	}

	// 3a. Validate credential format. The mock issuer supports the two
	// SD-JWT VC formats: legacy "vc+sd-jwt" and current "dc+sd-jwt" (SD-JWT
	// VC draft 06+). If the request carries an explicit `format`, it must
	// match the credential configuration's format.
	format := cfg.Format
	if !isSDJWTFormat(format) {
		h.writeError(w, http.StatusBadRequest, errCodeUnsupportedCredType,
			fmt.Sprintf("credential configuration %q has unsupported format %q (only vc+sd-jwt and dc+sd-jwt are supported)",
				configID, format))
		return
	}
	if req.Format != "" && req.Format != format {
		h.writeError(w, http.StatusBadRequest, errCodeUnsupportedCredType,
			fmt.Sprintf("request format %q does not match credential configuration format %q",
				req.Format, format))
		return
	}

	// 4. Validate proof and extract holder key
	holderKey, err := h.validateProof(ctx, req.Proofs)
	if err != nil {
		var oidcErr *OIDC4VCIError
		if errors.As(err, &oidcErr) {
			h.writeError(w, oidcErr.HTTPStatus, oidcErr.Code, oidcErr.Description)
		} else {
			h.writeError(w, http.StatusBadRequest, errCodeInvalidOrMissingProof, err.Error())
		}
		return
	}

	// 5. Sign credential
	credential, err := h.signer.IssueSDJWTVC(
		h.cfg.IssuerURL,
		tokenInfo.Subject,
		cfg.VCT,
		format,
		holderKey,
		nil,
	)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, errCodeServerError, "failed to sign credential")
		return
	}

	// 6. Generate fresh nonce for next request
	freshNonce, err := h.nonces.GenerateNonce(ctx)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, errCodeServerError, "failed to generate nonce")
		return
	}

	h.writeJSON(w, http.StatusOK, credentialResponse{
		Credentials:     []map[string]interface{}{{"credential": credential}},
		CNonce:          freshNonce.Value,
		CNonceExpiresIn: h.nonces.TTLSeconds(),
	})
}

// validateProof extracts and validates the JWT proof, consuming the nonce.
func (h *Handler) validateProof(ctx context.Context, proofs map[string]interface{}) (crypto.PublicKey, error) {
	if len(proofs) == 0 {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "proof is required")
	}
	jwtProofs, ok := proofs["jwt"]
	if !ok {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "only jwt proof type is supported")
	}

	var proofJWT string
	switch v := jwtProofs.(type) {
	case string:
		proofJWT = v
	case []interface{}:
		if len(v) == 0 {
			return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "jwt proof array is empty")
		}
		s, ok := v[0].(string)
		if !ok {
			return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "jwt proof must be a string")
		}
		proofJWT = s
	default:
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "invalid jwt proof format")
	}

	return h.parseAndValidateProofJWT(ctx, proofJWT)
}

// parseAndValidateProofJWT parses the proof JWT using stdlib only (no external JWT library).
// It verifies the ES256 signature using the JWK embedded in the header, validates the
// nonce (consuming it), and checks the iat claim.
func (h *Handler) parseAndValidateProofJWT(ctx context.Context, proofJWT string) (crypto.PublicKey, error) {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "proof JWT must have three parts")
	}

	// ── 1. Decode header ──────────────────────────────────────────────────────
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "failed to decode JWT header")
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "failed to parse JWT header")
	}

	// ── 2. Extract public key from jwk header ─────────────────────────────────
	jwkRaw, ok := header["jwk"]
	if !ok {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "jwk header is required in proof JWT")
	}
	jwkMap, ok := jwkRaw.(map[string]interface{})
	if !ok {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "jwk header must be an object")
	}
	holderKey, err := parseECPublicKeyFromJWK(jwkMap)
	if err != nil {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400,
			fmt.Sprintf("failed to parse holder JWK: %v", err))
	}

	// ── 3. Verify ES256 signature ─────────────────────────────────────────────
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "failed to decode JWT signature")
	}
	if len(sigBytes) != 64 {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "invalid ES256 signature length")
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	ecKey, ok := holderKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "proof JWK must be an EC key")
	}
	if !ecdsa.Verify(ecKey, digest[:], r, s) {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "proof JWT signature verification failed")
	}

	// ── 4. Decode and validate claims ─────────────────────────────────────────
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "failed to decode JWT payload")
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "failed to parse JWT claims")
	}

	// Validate nonce (single-use)
	nonce, ok := claims["nonce"].(string)
	if !ok || nonce == "" {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "nonce claim is required in proof JWT")
	}
	if err := h.nonces.ValidateAndConsume(ctx, nonce); err != nil {
		var oidcErr *OIDC4VCIError
		if errors.As(err, &oidcErr) {
			return nil, oidcErr
		}
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, err.Error())
	}

	// Validate iat
	iat, ok := claims["iat"].(float64)
	if !ok {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "iat claim is required in proof JWT")
	}
	issuedAt := time.Unix(int64(iat), 0)
	now := time.Now()
	const maxSkew = 5 * time.Minute
	if now.Sub(issuedAt) > maxSkew || issuedAt.After(now.Add(maxSkew)) {
		return nil, newOIDCError(errCodeInvalidOrMissingProof, 400, "proof JWT iat is out of range")
	}

	return holderKey, nil
}

// parseECPublicKeyFromJWK parses an EC P-256 public key from a JWK map using stdlib only.
func parseECPublicKeyFromJWK(jwk map[string]interface{}) (crypto.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	if kty != "EC" {
		return nil, fmt.Errorf("unsupported kty %q (only EC is supported)", kty)
	}
	crv, _ := jwk["crv"].(string)
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve %q (only P-256 is supported)", crv)
	}
	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)
	if xStr == "" || yStr == "" {
		return nil, fmt.Errorf("JWK missing x or y coordinate")
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	return pub, nil
}

// ── Admin: credential configurations ─────────────────────────────────────────

func (h *Handler) handleCreateCredentialConfig(w http.ResponseWriter, r *http.Request) {
	var cfg CredentialConfiguration
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if cfg.ID == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	cfg.CreatedAt = time.Now()
	cfg.UpdatedAt = cfg.CreatedAt
	if err := h.store.CreateCredentialConfiguration(r.Context(), &cfg); err != nil {
		if errors.Is(err, errAlreadyExists) {
			h.writeError(w, http.StatusConflict, "already_exists",
				fmt.Sprintf("credential configuration %q already exists", cfg.ID))
			return
		}
		h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusCreated, &cfg)
}

func (h *Handler) handleListCredentialConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := h.store.ListCredentialConfigurations(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, configs)
}

func (h *Handler) handleGetOrUpdateOrDeleteCredentialConfig(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/oidc4vci/credential-configurations/")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		cfg, err := h.store.GetCredentialConfiguration(ctx, id)
		if err != nil {
			if errors.Is(err, errNotFound) {
				h.writeError(w, http.StatusNotFound, "not_found", "credential configuration not found")
				return
			}
			h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
			return
		}
		h.writeJSON(w, http.StatusOK, cfg)

	case http.MethodPut:
		var cfg CredentialConfiguration
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}
		cfg.ID = id
		cfg.UpdatedAt = time.Now()
		if err := h.store.UpdateCredentialConfiguration(ctx, id, &cfg); err != nil {
			if errors.Is(err, errNotFound) {
				h.writeError(w, http.StatusNotFound, "not_found", "credential configuration not found")
				return
			}
			h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
			return
		}
		h.writeJSON(w, http.StatusOK, &cfg)

	case http.MethodDelete:
		if err := h.store.DeleteCredentialConfiguration(ctx, id); err != nil {
			if errors.Is(err, errNotFound) {
				h.writeError(w, http.StatusNotFound, "not_found", "credential configuration not found")
				return
			}
			h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		h.writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
	}
}

// ── Admin: credential offers ──────────────────────────────────────────────────

type createOfferRequest struct {
	ID                         string       `json:"id"`
	CredentialConfigurationIDs []string     `json:"credential_configuration_ids"`
	Grants                     *OfferGrants `json:"grants,omitempty"`
	ClientID                   string       `json:"client_id,omitempty"`
	Scope                      string       `json:"scope,omitempty"`
	Claims                     map[string]interface{} `json:"claims,omitempty"`
}

func (h *Handler) handleCreateCredentialOffer(w http.ResponseWriter, r *http.Request) {
	var req createOfferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if req.ID == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	if len(req.CredentialConfigurationIDs) == 0 {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "credential_configuration_ids is required")
		return
	}

	ctx := r.Context()

	// If the offer includes a pre-authorized code grant with no code yet, delegate to Hydra.
	if req.Grants != nil && req.Grants.PreAuthorizedCode != nil &&
		req.Grants.PreAuthorizedCode.PreAuthorizedCode == "" {
		var txCode, txCodeInputMode string
		var txCodeLength int
		if req.Grants.PreAuthorizedCode.TxCode != nil {
			txCode = req.Grants.PreAuthorizedCode.TxCode.Value
			txCodeInputMode = req.Grants.PreAuthorizedCode.TxCode.InputMode
			txCodeLength = req.Grants.PreAuthorizedCode.TxCode.Length
		}
		code, err := h.createPreAuthCodeViaHydra(ctx, req.CredentialConfigurationIDs, req.ClientID, req.Scope, txCode, txCodeInputMode, txCodeLength)
		if err != nil {
			h.writeError(w, http.StatusBadGateway, errCodeServerError,
				fmt.Sprintf("failed to create pre-authorized code via Hydra: %v", err))
			return
		}
		req.Grants.PreAuthorizedCode.PreAuthorizedCode = code
	}

	offer := &CredentialOffer{
		ID:                         req.ID,
		CredentialIssuer:           h.cfg.IssuerURL,
		CredentialConfigurationIDs: req.CredentialConfigurationIDs,
		Grants:                     req.Grants,
		CreatedAt:                  time.Now(),
		ExpiresAt:                  time.Now().Add(24 * time.Hour),
	}

	if err := h.store.CreateCredentialOffer(ctx, offer); err != nil {
		if errors.Is(err, errAlreadyExists) {
			h.writeError(w, http.StatusConflict, "already_exists",
				fmt.Sprintf("credential offer %q already exists", req.ID))
			return
		}
		h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusCreated, offer)
}

func (h *Handler) handleListCredentialOffers(w http.ResponseWriter, r *http.Request) {
	offers, err := h.store.ListCredentialOffers(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, offers)
}

func (h *Handler) handleGetOrDeleteCredentialOffer(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/oidc4vci/credential-offers/")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		offer, err := h.store.GetCredentialOffer(ctx, id)
		if err != nil {
			if errors.Is(err, errNotFound) {
				h.writeError(w, http.StatusNotFound, "not_found", "credential offer not found")
				return
			}
			h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
			return
		}
		h.writeJSON(w, http.StatusOK, offer)

	case http.MethodDelete:
		if err := h.store.DeleteCredentialOffer(ctx, id); err != nil {
			if errors.Is(err, errNotFound) {
				h.writeError(w, http.StatusNotFound, "not_found", "credential offer not found")
				return
			}
			h.writeError(w, http.StatusInternalServerError, errCodeServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		h.writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
	}
}

// createPreAuthCodeViaHydra calls Hydra's admin API to create a pre-authorized code.
// The admin endpoint is POST /admin/oauth2/preauth per the Hydra OIDC4VCI spec.
func (h *Handler) createPreAuthCodeViaHydra(ctx context.Context, configIDs []string, clientID string, scope string, txCode string, txCodeInputMode string, txCodeLength int) (string, error) {
	payload := map[string]interface{}{
		"credential_configuration_ids": configIDs,
	}
	if clientID != "" {
		payload["client_id"] = clientID
	}
	if scope != "" {
		payload["scope"] = scope
	}
	if txCode != "" {
		payload["tx_code"] = txCode
		if txCodeInputMode != "" {
			payload["tx_code_input_mode"] = txCodeInputMode
		}
		if txCodeLength > 0 {
			payload["tx_code_length"] = txCodeLength
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	endpoint := strings.TrimRight(h.cfg.AuthServerAdminURL, "/") + "/admin/oauth2/preauth"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Hydra returned HTTP %d: %s", resp.StatusCode, string(b))
	}
	var result struct {
		PreAuthorizedCode string `json:"pre_authorized_code"`
		ExpiresAt         string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode Hydra response: %w", err)
	}
	return result.PreAuthorizedCode, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, description string) {
	h.writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// extractAuthzHeader returns the authentication scheme (lowercased) and the
// credential from a request's Authorization header. OIDC4VCI accepts both
// `Bearer` (plain bearer) and `DPoP` (sender-constrained, RFC 9449 §7.1) as
// the scheme on the credential endpoint.
func extractAuthzHeader(r *http.Request) (scheme, credential string, err error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", fmt.Errorf("Authorization header is missing")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("Authorization header must be '<scheme> <credential>'")
	}
	return strings.ToLower(parts[0]), parts[1], nil
}
