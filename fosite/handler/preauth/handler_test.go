// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package preauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/fosite"
	foauth2 "github.com/ory/hydra/v2/fosite/handler/oauth2"
	"github.com/ory/hydra/v2/fosite/handler/openid"
	"github.com/ory/hydra/v2/fosite/handler/preauth"
	"github.com/ory/hydra/v2/fosite/token/jwt"
	oauth2session "github.com/ory/hydra/v2/oauth2"

	"github.com/ory/x/sqlxx"
)

// --- mock types ---

// mockStorage implements preauth.PreAuthorizedCodeStorage using an in-memory map.
type mockStorage struct {
	mu   sync.Mutex
	data map[string]*preauth.PreAuthorizedCodeData
}

func newMockStorage() *mockStorage {
	return &mockStorage{data: make(map[string]*preauth.PreAuthorizedCodeData)}
}

func (m *mockStorage) CreatePreAuthorizedCodeSession(_ context.Context, signature string, data *preauth.PreAuthorizedCodeData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[signature] = data
	return nil
}

func (m *mockStorage) GetPreAuthorizedCodeSession(_ context.Context, signature string) (*preauth.PreAuthorizedCodeData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.data[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	// Return a copy to avoid test mutations leaking.
	cp := *d
	return &cp, nil
}

func (m *mockStorage) InvalidatePreAuthorizedCode(_ context.Context, signature string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.data[signature]
	if !ok {
		return fmt.Errorf("not found")
	}
	if d.Redeemed {
		return fmt.Errorf("already redeemed")
	}
	d.Redeemed = true
	return nil
}

// AccessTokenStorage returns self — mockStorage also implements oauth2.AccessTokenStorage.
func (m *mockStorage) AccessTokenStorage() foauth2.AccessTokenStorage {
	return m
}

// PreAuthorizedCodeStorage returns self — mockStorage implements the provider interface.
func (m *mockStorage) PreAuthorizedCodeStorage() preauth.PreAuthorizedCodeStorage {
	return m
}

func (m *mockStorage) CreateAccessTokenSession(_ context.Context, _ string, _ fosite.Requester) error {
	return nil
}

func (m *mockStorage) GetAccessTokenSession(_ context.Context, _ string, _ fosite.Session) (fosite.Requester, error) {
	return nil, fosite.ErrNotFound
}

func (m *mockStorage) DeleteAccessTokenSession(_ context.Context, _ string) error {
	return nil
}

// mockStrategy implements preauth.CoreStrategy (oauth2.CoreStrategy) for testing.
// It returns predictable tokens and extracts signatures by splitting on ".".
type mockStrategy struct{}

func (m *mockStrategy) AuthorizeCodeSignature(_ context.Context, token string) string {
	// Mimic HMAC strategy: split on "." and return the second part.
	for i, c := range token {
		if c == '.' {
			return token[i+1:]
		}
	}
	return token
}

func (m *mockStrategy) GenerateAuthorizeCode(_ context.Context, _ fosite.Requester) (string, string, error) {
	return "code.sig", "sig", nil
}

func (m *mockStrategy) ValidateAuthorizeCode(_ context.Context, _ fosite.Requester, _ string) error {
	return nil
}

func (m *mockStrategy) AccessTokenSignature(_ context.Context, token string) string {
	return token
}

func (m *mockStrategy) GenerateAccessToken(_ context.Context, _ fosite.Requester) (string, string, error) {
	return "access-token-value", "at-sig", nil
}

func (m *mockStrategy) ValidateAccessToken(_ context.Context, _ fosite.Requester, _ string) error {
	return nil
}

func (m *mockStrategy) RefreshTokenSignature(_ context.Context, token string) string {
	return token
}

func (m *mockStrategy) GenerateRefreshToken(_ context.Context, _ fosite.Requester) (string, string, error) {
	return "refresh-token-value", "rt-sig", nil
}

func (m *mockStrategy) ValidateRefreshToken(_ context.Context, _ fosite.Requester, _ string) error {
	return nil
}

// mockConfig implements preauth.PreAuthorizedCodeConfigProvider plus
// fosite.AccessTokenLifespanProvider and fosite.RefreshTokenScopesProvider
// for PopulateTokenEndpointResponse.
type mockConfig struct {
	enabled         bool
	lifespan        time.Duration
	anonymousAccess bool
	atLifespan      time.Duration
	rtScopes        []string
}

func (c *mockConfig) GetPreAuthorizedCodeEnabled(_ context.Context) bool              { return c.enabled }
func (c *mockConfig) GetPreAuthorizedCodeLifespan(_ context.Context) time.Duration    { return c.lifespan }
func (c *mockConfig) GetPreAuthorizedCodeAnonymousAccess(_ context.Context) bool      { return c.anonymousAccess }
func (c *mockConfig) GetAccessTokenLifespan(_ context.Context) time.Duration          { return c.atLifespan }
func (c *mockConfig) GetRefreshTokenScopes(_ context.Context) []string                { return c.rtScopes }

// --- helpers ---

func defaultConfig() *mockConfig {
	return &mockConfig{
		enabled:         true,
		lifespan:        30 * time.Minute,
		anonymousAccess: false,
		atLifespan:      time.Hour,
		rtScopes:        []string{"offline", "offline_access"},
	}
}

func newHandler(store *mockStorage, cfg *mockConfig) *preauth.Handler {
	return &preauth.Handler{
		Config:   cfg,
		Storage:  store,
		Strategy: &mockStrategy{},
	}
}

// sha256Hex computes the SHA-256 hex digest of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// newTestSession creates a properly initialized oauth2session.Session for testing.
func newTestSession() *oauth2session.Session {
	return &oauth2session.Session{
		DefaultSession: &openid.DefaultSession{
			Claims:    &jwt.IDTokenClaims{},
			Headers:   &jwt.Headers{},
			ExpiresAt: make(map[fosite.TokenType]time.Time),
		},
		Extra: map[string]interface{}{},
	}
}

// marshalSession serializes an oauth2session.Session to JSON.
func marshalSession(t require.TestingT, s *oauth2session.Session) json.RawMessage {
	data, err := json.Marshal(s)
	require.NoError(t, err)
	return data
}

// newAccessRequest creates a fosite.AccessRequest with the pre-authorized code grant type,
// the given session, and the given client.
func newAccessRequest(session fosite.Session, client fosite.Client) *fosite.AccessRequest {
	ar := fosite.NewAccessRequest(session)
	ar.GrantTypes = fosite.Arguments{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}
	if client != nil {
		ar.Client = client
	}
	return ar
}

// --- rapid generators ---

func genCredentialConfigID() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_]{0,29}`)
}

func genCredentialConfigIDSet() *rapid.Generator[[]string] {
	return rapid.Custom(func(t *rapid.T) []string {
		n := rapid.IntRange(1, 5).Draw(t, "setSize")
		seen := make(map[string]bool)
		var ids []string
		for len(ids) < n {
			id := genCredentialConfigID().Draw(t, "id")
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		return ids
	})
}


// =============================================================================
// Feature: oidc4vci-preauth, Property 1: Pre-Authorized Code Valid Redemption
// =============================================================================

// TestProperty1_ValidRedemption verifies that for any valid pre-authorized code
// with associated CredentialConfigurationIDs, exchanging it produces an access
// token whose session contains authorization_details matching the stored config
// IDs, and the response includes access_token, token_type, and authorization_details.
//
// **Validates: Requirements 1.10, 4.2, 4.3, 4.4, 4.5, 13.1, 13.2, 13.3, 13.4, 17.3**
func TestProperty1_ValidRedemption(t *testing.T) {
	t.Parallel()

	t.Run("case=property 1 valid redemption", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-preauth, Property 1: Pre-Authorized Code Valid Redemption
		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			credIDs := genCredentialConfigIDSet().Draw(t, "credentialConfigIDs")
			clientID := rapid.StringMatching(`client-[a-z0-9]{4,10}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8,16}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()

			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat(credIDs),
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			client := &fosite.DefaultClient{
				ID:         clientID,
				GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code", "refresh_token"},
			}

			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)

			ctx := t.Context()

			// HandleTokenEndpointRequest should succeed.
			err = handler.HandleTokenEndpointRequest(ctx, ar)
			require.NoError(t, err, "HandleTokenEndpointRequest should succeed for valid code")

			// Session should have authorization_details.
			session, ok := ar.GetSession().(fosite.ExtraClaimsSession)
			require.True(t, ok, "session should implement ExtraClaimsSession")
			authDetailsRaw, exists := session.GetExtraClaims()["authorization_details"]
			require.True(t, exists, "session should contain authorization_details")

			authDetails, ok := authDetailsRaw.([]map[string]interface{})
			require.True(t, ok, "authorization_details should be []map[string]interface{}")
			require.Len(t, authDetails, len(credIDs), "authorization_details should have one entry per credential config ID")

			// Verify each credential_configuration_id is present.
			gotIDs := make(map[string]bool)
			for _, ad := range authDetails {
				assert.Equal(t, "openid_credential", ad["type"])
				if id, ok := ad["credential_configuration_id"].(string); ok {
					gotIDs[id] = true
				}
			}
			for _, id := range credIDs {
				assert.True(t, gotIDs[id], "authorization_details should contain credential_configuration_id %q", id)
			}

			// PopulateTokenEndpointResponse should succeed.
			resp := fosite.NewAccessResponse()
			err = handler.PopulateTokenEndpointResponse(ctx, ar, resp)
			require.NoError(t, err, "PopulateTokenEndpointResponse should succeed")

			// Verify response fields.
			assert.NotEmpty(t, resp.GetAccessToken(), "response should contain access_token")
			assert.Equal(t, "bearer", resp.GetTokenType(), "token_type should be bearer")
			assert.NotNil(t, resp.GetExtra("authorization_details"), "response should contain authorization_details")
		})
	})
}

// =============================================================================
// Feature: oidc4vci-preauth, Property 2: Pre-Authorized Code tx_code Validation
// =============================================================================

// TestProperty2_TxCodeValidation verifies all 5 combinations of stored TxCodeHash
// (empty/non-empty) × request tx_code (present/absent/matching/mismatching).
//
// **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6**
func TestProperty2_TxCodeValidation(t *testing.T) {
	t.Parallel()

	t.Run("case=property 2 tx_code validation", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-preauth, Property 2: Pre-Authorized Code tx_code Validation
		rapid.Check(t, func(t *rapid.T) {
			const (
				scenarioRequiredAndMatching    = 0
				scenarioRequiredAndMismatching = 1
				scenarioRequiredButMissing     = 2
				scenarioNotRequiredButProvided  = 3
				scenarioNeitherRequiredNorProvided = 4
			)

			scenario := rapid.IntRange(0, 4).Draw(t, "scenario")

			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			txCodePlaintext := rapid.StringMatching(`[0-9a-zA-Z]{4,12}`).Draw(t, "txCode")
			txCodeHash := sha256Hex(txCodePlaintext)
			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			var storedHash string
			var formTxCode string

			switch scenario {
			case scenarioRequiredAndMatching:
				storedHash = txCodeHash
				formTxCode = txCodePlaintext
			case scenarioRequiredAndMismatching:
				storedHash = txCodeHash
				formTxCode = txCodePlaintext + "wrong"
			case scenarioRequiredButMissing:
				storedHash = txCodeHash
				formTxCode = ""
			case scenarioNotRequiredButProvided:
				storedHash = ""
				formTxCode = txCodePlaintext
			case scenarioNeitherRequiredNorProvided:
				storedHash = ""
				formTxCode = ""
			}

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat{"CredA"},
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				TxCodeHash:                 storedHash,
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			client := &fosite.DefaultClient{ID: clientID, GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)
			if formTxCode != "" {
				ar.Form.Set("tx_code", formTxCode)
			}

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)

			switch scenario {
			case scenarioRequiredAndMatching:
				assert.NoError(t, err, "matching tx_code should be accepted")

			case scenarioRequiredAndMismatching:
				require.Error(t, err, "mismatching tx_code should be rejected")
				rfcErr := fosite.ErrorToRFC6749Error(err)
				assert.Equal(t, "invalid_grant", rfcErr.ErrorField, "error should be invalid_grant")

			case scenarioRequiredButMissing:
				require.Error(t, err, "missing tx_code when required should be rejected")
				rfcErr := fosite.ErrorToRFC6749Error(err)
				assert.Equal(t, "invalid_request", rfcErr.ErrorField, "error should be invalid_request")

			case scenarioNotRequiredButProvided:
				require.Error(t, err, "unexpected tx_code should be rejected")
				rfcErr := fosite.ErrorToRFC6749Error(err)
				assert.Equal(t, "invalid_request", rfcErr.ErrorField, "error should be invalid_request")

			case scenarioNeitherRequiredNorProvided:
				assert.NoError(t, err, "no tx_code required and none provided should succeed")
			}
		})
	})
}

// =============================================================================
// Feature: oidc4vci-preauth, Property 3: Pre-Authorized Code Client ID Validation
// =============================================================================

// TestProperty3_ClientIDValidation verifies that bound codes accept only matching
// clients and unbound codes accept any client.
//
// **Validates: Requirements 1.11, 1.12**
func TestProperty3_ClientIDValidation(t *testing.T) {
	t.Parallel()

	t.Run("case=property 3 client ID validation", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-preauth, Property 3: Pre-Authorized Code Client ID Validation
		rapid.Check(t, func(t *rapid.T) {
			const (
				scenarioBoundMatching    = 0
				scenarioBoundMismatching = 1
				scenarioUnbound          = 2
			)

			scenario := rapid.IntRange(0, 2).Draw(t, "scenario")

			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			boundClientID := rapid.StringMatching(`client-[a-z0-9]{4,8}`).Draw(t, "boundClientID")
			otherClientID := rapid.StringMatching(`other-[a-z0-9]{4,8}`).Draw(t, "otherClientID")
			// Ensure they differ.
			if otherClientID == boundClientID {
				otherClientID = otherClientID + "-x"
			}

			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			var storedClientID string
			var requestClientID string

			switch scenario {
			case scenarioBoundMatching:
				storedClientID = boundClientID
				requestClientID = boundClientID
			case scenarioBoundMismatching:
				storedClientID = boundClientID
				requestClientID = otherClientID
			case scenarioUnbound:
				storedClientID = ""
				requestClientID = rapid.StringMatching(`any-[a-z0-9]{4}`).Draw(t, "anyClientID")
			}

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   storedClientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat{"CredA"},
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			client := &fosite.DefaultClient{
				ID:         requestClientID,
				GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)

			switch scenario {
			case scenarioBoundMatching:
				assert.NoError(t, err, "bound code with matching client should be accepted")

			case scenarioBoundMismatching:
				require.Error(t, err, "bound code with mismatching client should be rejected")
				rfcErr := fosite.ErrorToRFC6749Error(err)
				assert.Equal(t, "invalid_grant", rfcErr.ErrorField, "error should be invalid_grant")

			case scenarioUnbound:
				assert.NoError(t, err, "unbound code should accept any client")
			}
		})
	})
}

// =============================================================================
// Feature: oidc4vci-preauth, Property 4: Pre-Authorized Code Single-Use Enforcement
// =============================================================================

// TestProperty4_SingleUseEnforcement verifies that the first redemption succeeds
// and any subsequent redemption fails with "pre-authorized code already redeemed".
//
// **Validates: Requirements 1.7, 1.9, 8.3**
func TestProperty4_SingleUseEnforcement(t *testing.T) {
	t.Parallel()

	t.Run("case=property 4 single-use enforcement", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-preauth, Property 4: Pre-Authorized Code Single-Use Enforcement
		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat{"CredA"},
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			client := &fosite.DefaultClient{
				ID:         clientID,
				GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			}

			// First redemption should succeed.
			ar1 := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar1.Form.Set("pre-authorized_code", rawCode)

			err = handler.HandleTokenEndpointRequest(t.Context(), ar1)
			require.NoError(t, err, "first redemption should succeed")

			// Second redemption should fail — code is already redeemed.
			// Re-create the storage entry as redeemed (the first call already set it).
			ar2 := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar2.Form.Set("pre-authorized_code", rawCode)

			err = handler.HandleTokenEndpointRequest(t.Context(), ar2)
			require.Error(t, err, "second redemption should fail")
			rfcErr := fosite.ErrorToRFC6749Error(err)
			assert.Equal(t, "invalid_grant", rfcErr.ErrorField, "error should be invalid_grant for redeemed code")
		})
	})
}

// =============================================================================
// Feature: oidc4vci-preauth, Property 5: Pre-Authorized Code Expiry Enforcement
// =============================================================================

// TestProperty5_ExpiryEnforcement verifies that expired codes are rejected and
// non-expired codes pass the expiry check.
//
// **Validates: Requirements 1.8**
func TestProperty5_ExpiryEnforcement(t *testing.T) {
	t.Parallel()

	t.Run("case=property 5 expiry enforcement", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-preauth, Property 5: Pre-Authorized Code Expiry Enforcement
		rapid.Check(t, func(t *rapid.T) {
			isExpired := rapid.Bool().Draw(t, "isExpired")

			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			var expiresAt time.Time
			if isExpired {
				// Expired: 1 minute to 1 hour in the past.
				pastSeconds := rapid.IntRange(60, 3600).Draw(t, "pastSeconds")
				expiresAt = time.Now().Add(-time.Duration(pastSeconds) * time.Second)
			} else {
				// Not expired: 1 minute to 1 hour in the future.
				futureSeconds := rapid.IntRange(60, 3600).Draw(t, "futureSeconds")
				expiresAt = time.Now().Add(time.Duration(futureSeconds) * time.Second)
			}

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat{"CredA"},
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  expiresAt,
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			client := &fosite.DefaultClient{
				ID:         clientID,
				GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)

			if isExpired {
				require.Error(t, err, "expired code should be rejected")
				rfcErr := fosite.ErrorToRFC6749Error(err)
				assert.Equal(t, "invalid_grant", rfcErr.ErrorField, "error should be invalid_grant for expired code")
			} else {
				assert.NoError(t, err, "non-expired code should pass expiry check")
			}
		})
	})
}

// =============================================================================
// Feature: oidc4vci-preauth, Property 6: Pre-Authorized Code authorization_details Subset Validation
// =============================================================================

// TestProperty6_AuthorizationDetailsSubsetValidation verifies that subset requests
// are accepted, non-subset requests are rejected, default set construction works
// when Wallet omits authorization_details, and empty array [] is rejected.
//
// **Validates: Requirements 17.1, 17.2, 17.4, 17.5**
func TestProperty6_AuthorizationDetailsSubsetValidation(t *testing.T) {
	t.Parallel()

	t.Run("case=property 6 authorization_details subset accepted", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-preauth, Property 6: Pre-Authorized Code authorization_details Subset Validation
		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			storedIDs := genCredentialConfigIDSet().Draw(t, "storedIDs")
			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat(storedIDs),
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			// Pick a non-empty subset of storedIDs.
			var subsetIDs []string
			for _, id := range storedIDs {
				if rapid.Bool().Draw(t, "include_"+id) {
					subsetIDs = append(subsetIDs, id)
				}
			}
			if len(subsetIDs) == 0 {
				subsetIDs = append(subsetIDs, storedIDs[0])
			}

			// Build authorization_details JSON.
			var adArray []map[string]interface{}
			for _, id := range subsetIDs {
				adArray = append(adArray, map[string]interface{}{
					"type":                        "openid_credential",
					"credential_configuration_id": id,
				})
			}
			adJSON, _ := json.Marshal(adArray)

			client := &fosite.DefaultClient{ID: clientID, GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)
			ar.Form.Set("authorization_details", string(adJSON))

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)
			assert.NoError(t, err, "subset authorization_details should be accepted")
		})
	})

	t.Run("case=property 6 authorization_details non-subset rejected", func(t *testing.T) {
		t.Parallel()

		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			storedIDs := genCredentialConfigIDSet().Draw(t, "storedIDs")
			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat(storedIDs),
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			// Generate an ID guaranteed not in storedIDs.
			storedSet := make(map[string]bool)
			for _, id := range storedIDs {
				storedSet[id] = true
			}
			var extraID string
			for {
				extraID = rapid.StringMatching(`extra_[a-z0-9]{1,10}`).Draw(t, "extraID")
				if !storedSet[extraID] {
					break
				}
			}

			adArray := []map[string]interface{}{
				{"type": "openid_credential", "credential_configuration_id": extraID},
			}
			adJSON, _ := json.Marshal(adArray)

			client := &fosite.DefaultClient{ID: clientID, GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)
			ar.Form.Set("authorization_details", string(adJSON))

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)
			require.Error(t, err, "non-subset authorization_details should be rejected")
			rfcErr := fosite.ErrorToRFC6749Error(err)
			assert.Equal(t, "invalid_request", rfcErr.ErrorField, "error should be invalid_request")
		})
	})

	t.Run("case=property 6 default set when authorization_details omitted", func(t *testing.T) {
		t.Parallel()

		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			storedIDs := genCredentialConfigIDSet().Draw(t, "storedIDs")
			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat(storedIDs),
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			client := &fosite.DefaultClient{ID: clientID, GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)
			// Do NOT set authorization_details — handler should construct default set.

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)
			require.NoError(t, err, "omitted authorization_details should succeed with default set")

			// Verify the session has authorization_details with all stored IDs.
			session, ok := ar.GetSession().(fosite.ExtraClaimsSession)
			require.True(t, ok)
			authDetailsRaw := session.GetExtraClaims()["authorization_details"]
			authDetails, ok := authDetailsRaw.([]map[string]interface{})
			require.True(t, ok)
			require.Len(t, authDetails, len(storedIDs))

			gotIDs := make(map[string]bool)
			for _, ad := range authDetails {
				assert.Equal(t, "openid_credential", ad["type"])
				if id, ok := ad["credential_configuration_id"].(string); ok {
					gotIDs[id] = true
				}
			}
			for _, id := range storedIDs {
				assert.True(t, gotIDs[id], "default set should contain %q", id)
			}
		})
	})

	t.Run("case=property 6 empty array rejected", func(t *testing.T) {
		t.Parallel()

		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			storedIDs := genCredentialConfigIDSet().Draw(t, "storedIDs")
			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat(storedIDs),
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			client := &fosite.DefaultClient{ID: clientID, GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)
			ar.Form.Set("authorization_details", "[]")

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)
			require.Error(t, err, "empty array authorization_details should be rejected")
			rfcErr := fosite.ErrorToRFC6749Error(err)
			assert.Equal(t, "invalid_request", rfcErr.ErrorField, "error should be invalid_request")
		})
	})
}

// =============================================================================
// Feature: oidc4vci-preauth, Property 7: Pre-Authorized Code Refresh Token Prohibition in Anonymous Mode
// =============================================================================

// TestProperty7_RefreshTokenProhibitionAnonymous verifies that unbound codes
// (anonymous) never get refresh tokens, bound codes with eligible clients do,
// and bound codes with ineligible clients do not.
//
// **Validates: Requirements 4.6, 4.7**
func TestProperty7_RefreshTokenProhibitionAnonymous(t *testing.T) {
	t.Parallel()

	t.Run("case=property 7 anonymous no refresh token", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-preauth, Property 7: Pre-Authorized Code Refresh Token Prohibition in Anonymous Mode
		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			cfg.anonymousAccess = true
			handler := newHandler(store, cfg)

			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   "", // unbound
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat{"CredA"},
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid", "offline"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			// Anonymous client (empty ID).
			client := &fosite.DefaultClient{
				ID:         "",
				GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code", "refresh_token"},
			}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)
			require.NoError(t, err)

			resp := fosite.NewAccessResponse()
			err = handler.PopulateTokenEndpointResponse(t.Context(), ar, resp)
			require.NoError(t, err)

			assert.NotEmpty(t, resp.GetAccessToken(), "access token should be issued")
			assert.Nil(t, resp.GetExtra("refresh_token"), "anonymous mode should NOT issue refresh token")
		})
	})

	t.Run("case=property 7 bound client with refresh_token grant and offline scope gets refresh token", func(t *testing.T) {
		t.Parallel()

		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat{"CredA"},
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid", "offline"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			client := &fosite.DefaultClient{
				ID:         clientID,
				GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code", "refresh_token"},
			}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)
			require.NoError(t, err)

			resp := fosite.NewAccessResponse()
			err = handler.PopulateTokenEndpointResponse(t.Context(), ar, resp)
			require.NoError(t, err)

			assert.NotEmpty(t, resp.GetAccessToken(), "access token should be issued")
			assert.NotNil(t, resp.GetExtra("refresh_token"), "bound client with refresh_token grant + offline scope should get refresh token")
		})
	})

	t.Run("case=property 7 bound client without refresh_token grant gets no refresh token", func(t *testing.T) {
		t.Parallel()

		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat{"CredA"},
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid", "offline"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			// Client does NOT have refresh_token grant type.
			client := &fosite.DefaultClient{
				ID:         clientID,
				GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)
			require.NoError(t, err)

			resp := fosite.NewAccessResponse()
			err = handler.PopulateTokenEndpointResponse(t.Context(), ar, resp)
			require.NoError(t, err)

			assert.NotEmpty(t, resp.GetAccessToken(), "access token should be issued")
			assert.Nil(t, resp.GetExtra("refresh_token"), "client without refresh_token grant should NOT get refresh token")
		})
	})

	t.Run("case=property 7 bound client without offline scope gets no refresh token", func(t *testing.T) {
		t.Parallel()

		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()
			cfg := defaultConfig()
			handler := newHandler(store, cfg)

			clientID := rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID")
			signature := rapid.StringMatching(`sig-[a-z0-9]{8}`).Draw(t, "signature")
			rawCode := "key." + signature

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat{"CredA"},
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"}, // no offline scope
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			err := store.CreatePreAuthorizedCodeSession(t.Context(), signature, data)
			require.NoError(t, err)

			// Client HAS refresh_token grant type but no offline scope.
			client := &fosite.DefaultClient{
				ID:         clientID,
				GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code", "refresh_token"},
			}
			ar := newAccessRequest(&fosite.DefaultSession{Extra: map[string]interface{}{}}, client)
			ar.Form.Set("pre-authorized_code", rawCode)

			err = handler.HandleTokenEndpointRequest(t.Context(), ar)
			require.NoError(t, err)

			resp := fosite.NewAccessResponse()
			err = handler.PopulateTokenEndpointResponse(t.Context(), ar, resp)
			require.NoError(t, err)

			assert.NotEmpty(t, resp.GetAccessToken(), "access token should be issued")
			assert.Nil(t, resp.GetExtra("refresh_token"), "client without offline scope should NOT get refresh token")
		})
	})
}

// =============================================================================
// Feature: oidc4vci-preauth, Property 8: Pre-Authorized Code Storage Round-Trip
// =============================================================================

// TestProperty8_StorageRoundTrip verifies that for any valid PreAuthorizedCodeData,
// calling CreatePreAuthorizedCodeSession followed by GetPreAuthorizedCodeSession
// returns data equivalent to the original — all fields are preserved. Also verifies
// that InvalidatePreAuthorizedCode sets redeemed=true atomically and returns an
// error on a second call.
//
// **Validates: Requirements 5.1, 8.1, 8.2, 8.3**
func TestProperty8_StorageRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("case=property 8 create then get preserves all fields", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-preauth, Property 8: Pre-Authorized Code Storage Round-Trip
		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()

			signature := rapid.StringMatching(`sig-[a-z0-9]{8,16}`).Draw(t, "signature")

			// ClientID: sometimes empty for unbound codes.
			clientID := ""
			if rapid.Bool().Draw(t, "hasClientID") {
				clientID = rapid.StringMatching(`client-[a-z0-9]{4,10}`).Draw(t, "clientID")
			}

			// CredentialConfigurationIDs: 1-5 random IDs.
			credIDs := genCredentialConfigIDSet().Draw(t, "credentialConfigIDs")

			// TxCodeHash: sometimes empty.
			txCodeHash := ""
			if rapid.Bool().Draw(t, "hasTxCode") {
				txCodeHash = sha256Hex(rapid.StringMatching(`[0-9a-zA-Z]{4,12}`).Draw(t, "txCodePlaintext"))
			}

			// TxCodeInputMode: "numeric", "text", or empty.
			txCodeInputMode := rapid.SampledFrom([]string{"", "numeric", "text"}).Draw(t, "txCodeInputMode")

			// TxCodeLength: 0-10.
			txCodeLength := rapid.IntRange(0, 10).Draw(t, "txCodeLength")

			// SessionData: valid JSON.
			sess := newTestSession()
			sessionData := marshalSession(t, sess)

			// RequestedScope and GrantedScope.
			scopePool := []string{"openid", "offline", "profile", "email", "address"}
			nReq := rapid.IntRange(1, len(scopePool)).Draw(t, "nRequestedScope")
			nGrant := rapid.IntRange(1, nReq).Draw(t, "nGrantedScope")
			requestedScope := fosite.Arguments(scopePool[:nReq])
			grantedScope := fosite.Arguments(scopePool[:nGrant])

			// ExpiresAt: future timestamp (1 min to 2 hours from now).
			futureSeconds := rapid.IntRange(60, 7200).Draw(t, "futureSeconds")
			expiresAt := time.Now().Add(time.Duration(futureSeconds) * time.Second).Truncate(time.Second)
			requestedAt := time.Now().Truncate(time.Second)

			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   clientID,
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat(credIDs),
				TxCodeHash:                 txCodeHash,
				TxCodeInputMode:            txCodeInputMode,
				TxCodeLength:               txCodeLength,
				SessionData:                sessionData,
				RequestedScope:             sqlxx.StringSliceJSONFormat(requestedScope),
				GrantedScope:               sqlxx.StringSliceJSONFormat(grantedScope),
				Redeemed:                   false,
				ExpiresAt:                  expiresAt,
				RequestedAt:                requestedAt,
			}

			ctx := t.Context()

			// Create the session.
			err := store.CreatePreAuthorizedCodeSession(ctx, signature, data)
			require.NoError(t, err)

			// Get the session back.
			got, err := store.GetPreAuthorizedCodeSession(ctx, signature)
			require.NoError(t, err)

			// Verify all fields are preserved.
			assert.Equal(t, data.Signature, got.Signature, "Signature mismatch")
			assert.Equal(t, data.ClientID, got.ClientID, "ClientID mismatch")
			assert.Equal(t, []string(data.CredentialConfigurationIDs), []string(got.CredentialConfigurationIDs), "CredentialConfigurationIDs mismatch")
			assert.Equal(t, data.TxCodeHash, got.TxCodeHash, "TxCodeHash mismatch")
			assert.Equal(t, data.TxCodeInputMode, got.TxCodeInputMode, "TxCodeInputMode mismatch")
			assert.Equal(t, data.TxCodeLength, got.TxCodeLength, "TxCodeLength mismatch")
			assert.JSONEq(t, string(data.SessionData), string(got.SessionData), "SessionData mismatch")
			assert.Equal(t, []string(data.RequestedScope), []string(got.RequestedScope), "RequestedScope mismatch")
			assert.Equal(t, []string(data.GrantedScope), []string(got.GrantedScope), "GrantedScope mismatch")
			assert.Equal(t, data.Redeemed, got.Redeemed, "Redeemed mismatch")
			assert.True(t, data.ExpiresAt.Equal(got.ExpiresAt), "ExpiresAt mismatch: want %v, got %v", data.ExpiresAt, got.ExpiresAt)
			assert.True(t, data.RequestedAt.Equal(got.RequestedAt), "RequestedAt mismatch: want %v, got %v", data.RequestedAt, got.RequestedAt)
		})
	})

	t.Run("case=property 8 invalidate sets redeemed and second call fails", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-preauth, Property 8: Pre-Authorized Code Storage Round-Trip
		rapid.Check(t, func(t *rapid.T) {
			store := newMockStorage()

			signature := rapid.StringMatching(`sig-[a-z0-9]{8,16}`).Draw(t, "signature")

			sess := newTestSession()
			data := &preauth.PreAuthorizedCodeData{
				Signature:                  signature,
				ClientID:                   rapid.StringMatching(`client-[a-z0-9]{4}`).Draw(t, "clientID"),
				CredentialConfigurationIDs: sqlxx.StringSliceJSONFormat(genCredentialConfigIDSet().Draw(t, "credIDs")),
				GrantedScope:               sqlxx.StringSliceJSONFormat{"openid"},
				SessionData:                marshalSession(t, sess),
				Redeemed:                   false,
				ExpiresAt:                  time.Now().Add(30 * time.Minute),
				RequestedAt:                time.Now(),
			}

			ctx := t.Context()

			err := store.CreatePreAuthorizedCodeSession(ctx, signature, data)
			require.NoError(t, err)

			// First invalidation should succeed.
			err = store.InvalidatePreAuthorizedCode(ctx, signature)
			require.NoError(t, err, "first invalidation should succeed")

			// Verify redeemed is now true.
			got, err := store.GetPreAuthorizedCodeSession(ctx, signature)
			require.NoError(t, err)
			assert.True(t, got.Redeemed, "redeemed should be true after invalidation")

			// Second invalidation should fail (already redeemed).
			err = store.InvalidatePreAuthorizedCode(ctx, signature)
			require.Error(t, err, "second invalidation should fail because code is already redeemed")
		})
	})
}
