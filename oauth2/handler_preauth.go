// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	puuid "github.com/pborman/uuid"
	"github.com/pkg/errors"

	"github.com/ory/x/errorsx"
	"github.com/ory/x/sqlxx"

	"github.com/ory/hydra/v2/fosite"
)

// OIDC4VCI extension — Pre-Authorized Code admin API types and handler.

// preauthPath is the admin API path for pre-authorized code creation.
const preauthPath = "/oauth2/preauth"

// preauthSessionCreator is the subset of the registry needed to persist
// pre-authorized code data. Satisfied by *driver.RegistrySQL at runtime via
// its CreatePreauthSession method. Defined locally to avoid an import cycle
// between the oauth2 and fosite/handler/preauth packages.
type preauthSessionCreator interface {
	CreatePreauthSession(ctx context.Context, data interface{}) error
}

// preauthCodeData mirrors preauth.PreAuthorizedCodeData with the same Pop
// struct tags and table name. Defined locally to break the import cycle.
type preauthCodeData struct {
	Signature                  string                     `db:"signature"`
	NID                        uuid.UUID                  `db:"nid"`
	RequestID                  string                     `db:"request_id"`
	ClientID                   string                     `db:"client_id"`
	RequestedScope             fosite.Arguments           `db:"requested_scope"`
	GrantedScope               fosite.Arguments           `db:"granted_scope"`
	CredentialConfigurationIDs sqlxx.StringSliceJSONFormat `db:"credential_configuration_ids"`
	TxCodeHash                 string                     `db:"tx_code_hash"`
	TxCodeInputMode            string                     `db:"tx_code_input_mode"`
	TxCodeLength               int                        `db:"tx_code_length"`
	SessionData                json.RawMessage            `db:"session_data"`
	Redeemed                   bool                       `db:"redeemed"`
	RequestedAt                time.Time                  `db:"requested_at"`
	ExpiresAt                  time.Time                  `db:"expires_at"`
}

func (d *preauthCodeData) TableName() string {
	return "hydra_oauth2_preauth_code"
}

// Create Pre-Authorized Code Request
//
// swagger:parameters createPreAuthorizedCode
type createPreAuthorizedCodeRequest struct {
	// in: body
	// required: true
	Body createPreAuthorizedCodeBody
}

// swagger:model createPreAuthorizedCodeBody
type createPreAuthorizedCodeBody struct {
	// The OAuth 2.0 client ID to bind the code to.
	// If omitted, any client (or anonymous if configured) can redeem the code.
	//
	// example: wallet-app
	ClientID string `json:"client_id,omitempty"`

	// The credential configuration IDs the Credential Issuer plans to offer.
	// Defines the authorization envelope — the Wallet can request a subset
	// via authorization_details at the token endpoint.
	//
	// required: true
	// example: ["UniversityDegree_JWT", "org.iso.18013.5.1.mDL"]
	CredentialConfigurationIDs []string `json:"credential_configuration_ids"`

	// Space-separated scopes to grant. Include "offline" or "offline_access"
	// to enable refresh token issuance.
	//
	// example: UniversityDegree_JWT offline
	Scope string `json:"scope,omitempty"`

	// Transaction code in plaintext. The AS computes the SHA-256 hash before
	// storage. The plaintext is never stored.
	//
	// example: 493536
	TxCode string `json:"tx_code,omitempty"`

	// Input mode for the transaction code: "numeric" or "text".
	// Stored for metadata completeness (included in Credential Offer by the Issuer).
	//
	// example: numeric
	// enum: numeric,text
	TxCodeInputMode string `json:"tx_code_input_mode,omitempty"`

	// Expected length of the transaction code.
	// Stored for metadata completeness.
	//
	// example: 6
	TxCodeLength int `json:"tx_code_length,omitempty"`
}

// Pre-Authorized Code Response
//
// swagger:model preAuthorizedCodeResponse
type preAuthorizedCodeResponse struct {
	// The raw opaque pre-authorized code for inclusion in the Credential Offer.
	//
	// required: true
	// example: oaKazRN8I0IbtZ0C7JuMn5.base64hmac
	PreAuthorizedCode string `json:"pre_authorized_code"`

	// RFC 3339 expiry timestamp for the pre-authorized code.
	//
	// required: true
	// example: 2026-04-16T15:30:00Z
	ExpiresAt string `json:"expires_at"`
}

// swagger:route POST /admin/oauth2/preauth oAuth2 createPreAuthorizedCode
//
// # Create Pre-Authorized Code
//
// Create a pre-authorized code for inclusion in a Credential Offer. The Credential Issuer
// calls this endpoint to obtain a code that a Wallet can later exchange at the token endpoint
// for an access token. The code is bound to the specified credential configuration IDs
// (the authorization envelope) and optionally to a specific client_id.
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
//	Schemes: http, https
//
//	Responses:
//	  201: preAuthorizedCodeResponse
//	  400: errorOAuth2
//	  default: errorOAuth2
//
//	Extensions:
//	  x-ory-ratelimit-bucket: hydra-admin-high
func (h *Handler) createPreAuthorizedCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body createPreAuthorizedCodeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("unable to decode JSON body").WithDebugf("json decode error: %s", err.Error())))
		return
	}

	// Validate credential_configuration_ids is non-empty.
	if len(body.CredentialConfigurationIDs) == 0 {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("credential_configuration_ids is required and must be non-empty")))
		return
	}

	// If client_id provided, validate it corresponds to a registered client.
	if body.ClientID != "" {
		if _, err := h.r.ClientManager().GetClient(ctx, body.ClientID); err != nil {
			h.r.Writer().WriteError(w, r, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("client_id does not correspond to a registered client").WithDebugf("client lookup error: %s", err.Error())))
			return
		}
	}

	// Access the session creator via type assertion on the registry.
	// At runtime h.r is *driver.RegistrySQL which has CreatePreauthSession.
	creator, ok := h.r.(preauthSessionCreator)
	if !ok {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(fosite.ErrServerError.WithHint("pre-authorized code storage not available")))
		return
	}

	// Generate pre-authorized code via the HMAC strategy.
	// GenerateAuthorizeCode returns (token, signature, error) where token is the
	// raw code and signature is the DB primary key.
	token, signature, err := h.r.OAuth2HMACStrategy().GenerateAuthorizeCode(ctx, nil)
	if err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error())))
		return
	}

	// Compute SHA-256 hash of tx_code if provided.
	var txCodeHash string
	if body.TxCode != "" {
		hash := sha256.Sum256([]byte(body.TxCode))
		txCodeHash = hex.EncodeToString(hash[:])
	}

	// Compute expiry.
	now := time.Now().UTC()
	expiresAt := now.Add(h.c.GetPreAuthorizedCodeLifespan(ctx))

	// Parse scopes.
	var requestedScope, grantedScope fosite.Arguments
	if body.Scope != "" {
		scopes := strings.Fields(body.Scope)
		requestedScope = scopes
		grantedScope = scopes
	}

	// Build session data — minimal empty session.
	sessionData, _ := json.Marshal(&Session{})

	// Build pre-authorized code data for persistence.
	// Uses preauthCodeData (local mirror of preauth.PreAuthorizedCodeData)
	// to avoid the import cycle.
	data := &preauthCodeData{
		Signature:                  signature,
		RequestID:                  puuid.New(),
		ClientID:                   body.ClientID,
		RequestedScope:             requestedScope,
		GrantedScope:               grantedScope,
		CredentialConfigurationIDs: body.CredentialConfigurationIDs,
		TxCodeHash:                 txCodeHash,
		TxCodeInputMode:            body.TxCodeInputMode,
		TxCodeLength:               body.TxCodeLength,
		SessionData:                sessionData,
		Redeemed:                   false,
		RequestedAt:                now,
		ExpiresAt:                  expiresAt,
	}

	// Store via CreatePreauthSession which delegates to
	// BasePersister.CreateWithNetwork (sets NID automatically via reflection).
	if err := creator.CreatePreauthSession(ctx, data); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}

	// Return 201 with the raw code and expiry.
	h.r.Writer().WriteCreated(w, r, preauthPath, &preAuthorizedCodeResponse{
		PreAuthorizedCode: token,
		ExpiresAt:         expiresAt.Format(time.RFC3339),
	})
}
