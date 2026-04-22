// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
)

// DPoPConfigProvider is a type alias for the fosite.DPoPConfigProvider interface,
// allowing external packages to reference it without importing fosite directly.
type DPoPConfigProvider = fosite.DPoPConfigProvider

// dpopValidatedJKTContextKey stores the validated JKT string between
// HandleTokenEndpointRequest and PopulateTokenEndpointResponse.
type dpopContextKey string

const dpopValidatedJKTContextKey dpopContextKey = "dpop_validated_jkt"

// iatFutureTolerance is the hardcoded clock-skew tolerance for DPoP proof
// iat claims that are slightly in the future (5 seconds per design).
const iatFutureTolerance = 5 * time.Second

// Handler validates DPoP proofs on token and PAR requests per RFC 9449.
type Handler struct {
	Config     DPoPConfigProvider
	NonceStore DPoPNonceStorageProvider
}

// nonceStorage returns the concrete DPoPNonceStorage from the provider.
func (h *Handler) nonceStorage() DPoPNonceStorage {
	return h.NonceStore.DPoPNonceStorage()
}

// Compile-time interface satisfaction checks.
var _ fosite.PushedAuthorizeEndpointHandler = (*Handler)(nil)

// HandlePushedAuthorizeEndpointRequest validates DPoP proofs and dpop_jkt on
// PAR requests per RFC 9449 §10.
//
// When a DPoP proof is present, the handler validates it per §4.3 (adapted for
// PAR: htm=POST, htu from GetDPoPPARURLs) and computes the JKT. If both a
// dpop_jkt parameter and a DPoP proof are present, the handler verifies the
// thumbprints match. The computed JKT is stored in the request form as dpop_jkt
// for PAR session persistence.
//
// When only dpop_jkt is present (no DPoP proof), the handler validates it is
// non-empty and leaves it in the form.
//
// When neither is present, the handler returns nil (not responsible).
func (h *Handler) HandlePushedAuthorizeEndpointRequest(ctx context.Context, requester fosite.AuthorizeRequester, responder fosite.PushedAuthorizeResponder) error {
	form := requester.GetRequestForm()
	dpopJKT := form.Get("dpop_jkt")
	dpopProof := form.Get("dpop_proof")
	dpopProofError := form.Get("dpop_proof_error")

	// If neither dpop_jkt nor dpop_proof (nor a proof error) is present,
	// this handler is not responsible.
	if dpopJKT == "" && dpopProof == "" && dpopProofError == "" {
		return nil
	}

	// If a DPoP proof is present (or a proof error was flagged), validate it.
	if dpopProof != "" || dpopProofError != "" {
		allowedURLs := h.Config.GetDPoPPARURLs(ctx)
		computedJKT, _, err := h.validateDPoPProof(ctx, form, allowedURLs)
		if err != nil {
			return err
		}

		// If both dpop_jkt parameter and DPoP header are present, verify
		// the thumbprints match (RFC 9449 §10).
		if dpopJKT != "" && dpopJKT != computedJKT {
			return errors.WithStack(
				ErrInvalidDPoPProof.
					WithHint("The dpop_jkt parameter does not match the DPoP proof public key thumbprint.").
					WithDebugf("dpop_jkt=%q != computed jkt=%q", dpopJKT, computedJKT),
			)
		}

		// Store the computed JKT as dpop_jkt in the request form so it is
		// persisted as part of the PAR session.
		form.Set("dpop_jkt", computedJKT)
		return nil
	}

	// Only dpop_jkt parameter is present (no DPoP proof). Validate non-empty.
	if dpopJKT == "" {
		return errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The dpop_jkt parameter must not be empty.").
				WithDebugf("dpop_jkt is empty string"),
		)
	}

	// dpop_jkt is already in the form — no action needed.
	return nil
}

// dpopClaims holds the DPoP proof JWT claims we need to validate.
type dpopClaims struct {
	JTI   string           `json:"jti"`
	HTM   string           `json:"htm"`
	HTU   string           `json:"htu"`
	IAT   *jwt.NumericDate `json:"iat"`
	Nonce string           `json:"nonce"`
}

// validateDPoPProof implements the full RFC 9449 §4.3 checklist (12 checks).
// It returns the computed JWK Thumbprint (base64url-encoded), an updated
// context (with nonce if needed), and an error if validation fails.
func (h *Handler) validateDPoPProof(ctx context.Context, form url.Values, allowedURLs []string) (string, context.Context, error) {
	// Check 1: Single header check — reject if multiple DPoP headers were present.
	if form.Get("dpop_proof_error") == "multiple_headers" {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("Multiple DPoP headers present in the request.").
				WithDebugf("dpop_proof_error=multiple_headers"),
		)
	}

	proofString := form.Get("dpop_proof")
	if proofString == "" {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof is missing from the request.").
				WithDebugf("dpop_proof form parameter is empty"),
		)
	}

	// Check 2: Well-formed JWT parsing.
	parsedJWT, err := jwt.ParseSigned(proofString)
	if err != nil {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof is not a well-formed JWT.").
				WithDebugf("jwt parse error: %s", err.Error()),
		)
	}

	if len(parsedJWT.Headers) != 1 {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof must have exactly one JOSE header.").
				WithDebugf("got %d headers", len(parsedJWT.Headers)),
		)
	}

	header := parsedJWT.Headers[0]

	// Check 4: typ header is dpop+jwt.
	typRaw, ok := header.ExtraHeaders[jose.HeaderKey(jose.HeaderType)]
	if !ok {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof is missing the typ JOSE header.").
				WithDebugf("typ header not present"),
		)
	}
	typStr, _ := typRaw.(string)
	if !strings.EqualFold(typStr, "dpop+jwt") {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof typ header must be dpop+jwt.").
				WithDebugf("got typ=%q", typStr),
		)
	}

	// Check 5: alg header is a supported asymmetric algorithm.
	alg := header.Algorithm
	if err := h.validateAlgorithm(ctx, alg); err != nil {
		return "", ctx, err
	}

	// Check 6 (part 1): Extract public key from jwk header.
	jwk := header.JSONWebKey
	if jwk == nil {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof is missing the jwk JOSE header.").
				WithDebugf("jwk header not present"),
		)
	}

	// Check 7: No private key material in jwk.
	if err := validateNoPrivateKey(jwk); err != nil {
		return "", ctx, err
	}

	// Check 6 (part 2): Verify signature with embedded public key.
	// In go-jose/v3, Claims() both verifies the signature and extracts claims.
	var claims dpopClaims
	if err := parsedJWT.Claims(jwk.Key, &claims); err != nil {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof signature is invalid.").
				WithDebugf("signature verification error: %s", err.Error()),
		)
	}

	// Check 3: Required claims presence (jti, htm, htu, iat).
	if claims.JTI == "" {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof is missing the jti claim.").
				WithDebugf("jti claim is empty"),
		)
	}
	if claims.HTM == "" {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof is missing the htm claim.").
				WithDebugf("htm claim is empty"),
		)
	}
	if claims.HTU == "" {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof is missing the htu claim.").
				WithDebugf("htu claim is empty"),
		)
	}
	if claims.IAT == nil {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof is missing the iat claim.").
				WithDebugf("iat claim is nil"),
		)
	}

	// Check 8: htm claim matches POST.
	if !strings.EqualFold(claims.HTM, "POST") {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof htm claim must be POST.").
				WithDebugf("got htm=%q", claims.HTM),
		)
	}

	// Check 9: htu claim matches configured endpoint URLs after normalization.
	if !matchesAnyURL(claims.HTU, allowedURLs) {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof htu claim does not match the expected endpoint URL.").
				WithDebugf("htu=%q not in allowed URLs", claims.HTU),
		)
	}

	// Check 10: Nonce validation when enabled.
	if h.Config.GetDPoPNonceEnabled(ctx) {
		if claims.Nonce == "" {
			freshNonce, nonceErr := h.nonceStorage().CreateDPoPNonce(ctx)
			if nonceErr != nil {
				return "", ctx, errors.WithStack(
					ErrInvalidDPoPProof.
						WithHint("Failed to generate DPoP nonce.").
						WithDebugf("nonce creation error: %s", nonceErr.Error()),
				)
			}
			if noncePtr, ok := ctx.Value(DPoPNonceContextKey).(*string); ok && noncePtr != nil {
				*noncePtr = freshNonce
			}
			return "", ctx, errors.WithStack(
				ErrUseDPoPNonce.
					WithHint("The DPoP proof must include a server-issued nonce."),
			)
		}

		valid, nonceErr := h.nonceStorage().ValidateDPoPNonce(ctx, claims.Nonce)
		if nonceErr != nil {
			return "", ctx, errors.WithStack(
				ErrInvalidDPoPProof.
					WithHint("Failed to validate DPoP nonce.").
					WithDebugf("nonce validation error: %s", nonceErr.Error()),
			)
		}
		if !valid {
			freshNonce, createErr := h.nonceStorage().CreateDPoPNonce(ctx)
			if createErr != nil {
				return "", ctx, errors.WithStack(
					ErrInvalidDPoPProof.
						WithHint("Failed to generate DPoP nonce.").
						WithDebugf("nonce creation error: %s", createErr.Error()),
				)
			}
			if noncePtr, ok := ctx.Value(DPoPNonceContextKey).(*string); ok && noncePtr != nil {
				*noncePtr = freshNonce
			}
			return "", ctx, errors.WithStack(
				ErrUseDPoPNonce.
					WithHint("The DPoP proof nonce is invalid or expired."),
			)
		}
	}

	// Check 11: iat freshness within [now - maxAge, now + 5s].
	now := time.Now()
	maxAge := h.Config.GetDPoPProofMaxAge(ctx)
	iat := claims.IAT.Time()
	if iat.Before(now.Add(-maxAge)) {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof iat claim is too old.").
				WithDebugf("iat=%v is before now-maxAge=%v", iat, now.Add(-maxAge)),
		)
	}
	if iat.After(now.Add(iatFutureTolerance)) {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof iat claim is too far in the future.").
				WithDebugf("iat=%v is after now+5s=%v", iat, now.Add(iatFutureTolerance)),
		)
	}

	// Check 12: JTI uniqueness.
	used, err := h.nonceStorage().IsJTIUsed(ctx, claims.JTI)
	if err != nil {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("Failed to check DPoP proof JTI uniqueness.").
				WithDebugf("jti check error: %s", err.Error()),
		)
	}
	if used {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof jti has already been used.").
				WithDebugf("jti=%q is a replay", claims.JTI),
		)
	}
	if err := h.nonceStorage().MarkJTIUsed(ctx, claims.JTI, now.Add(maxAge)); err != nil {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("Failed to record DPoP proof JTI.").
				WithDebugf("jti mark error: %s", err.Error()),
		)
	}

	// Compute JWK Thumbprint (RFC 7638) using SHA-256.
	thumbprintBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", ctx, errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("Failed to compute JWK Thumbprint.").
				WithDebugf("thumbprint error: %s", err.Error()),
		)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumbprintBytes)

	return jkt, ctx, nil
}

// validateAlgorithm checks that the alg header is a supported asymmetric
// algorithm from the configuration.
func (h *Handler) validateAlgorithm(ctx context.Context, alg string) error {
	if alg == "" || alg == "none" {
		return errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof alg header must be a supported asymmetric algorithm.").
				WithDebugf("alg=%q is not allowed", alg),
		)
	}

	// Reject symmetric algorithms (HS*).
	if strings.HasPrefix(alg, "HS") {
		return errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof alg header must not be a symmetric algorithm.").
				WithDebugf("alg=%q is symmetric", alg),
		)
	}

	supported := h.Config.GetDPoPSigningAlgValuesSupported(ctx)
	for _, s := range supported {
		if s == alg {
			return nil
		}
	}

	return errors.WithStack(
		ErrInvalidDPoPProof.
			WithHint("The DPoP proof alg header is not in the supported algorithms list.").
			WithDebugf("alg=%q not in %v", alg, supported),
	)
}

// validateNoPrivateKey checks that the JWK does not contain private key
// material. For RSA keys, a private key is *rsa.PrivateKey; for EC keys,
// *ecdsa.PrivateKey. Public keys are *rsa.PublicKey and *ecdsa.PublicKey.
func validateNoPrivateKey(jwk *jose.JSONWebKey) error {
	switch jwk.Key.(type) {
	case *rsa.PrivateKey:
		return errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof jwk contains private key material.").
				WithDebugf("jwk key type is *rsa.PrivateKey"),
		)
	case *ecdsa.PrivateKey:
		return errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof jwk contains private key material.").
				WithDebugf("jwk key type is *ecdsa.PrivateKey"),
		)
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return nil
	default:
		// For ed25519 or other key types, check if it's a public-only key
		// by verifying the key is not nil. go-jose parses JWKs with "d"
		// field as private key types, so if we reach here with a non-nil
		// key it should be a public key type.
		if jwk.Key == nil {
			return errors.WithStack(
				ErrInvalidDPoPProof.
					WithHint("The DPoP proof jwk does not contain a valid key.").
					WithDebugf("jwk key is nil"),
			)
		}
		return nil
	}
}

// normalizeURL applies RFC 3986 §6.2.2–6.2.3 normalization:
// lowercase scheme and host, remove default ports, normalize path.
func normalizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Lowercase scheme and host.
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)

	// Remove default ports.
	host := parsed.Hostname()
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		parsed.Host = host
	}

	// Normalize path: remove trailing slash for comparison (but keep root "/").
	if len(parsed.Path) > 1 {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
	}

	// Strip query and fragment for htu comparison.
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String()
}

// matchesAnyURL checks if the htu claim matches any of the allowed URLs
// after RFC 3986 normalization.
func matchesAnyURL(htu string, allowedURLs []string) bool {
	normalizedHTU := normalizeURL(htu)
	for _, allowed := range allowedURLs {
		if normalizeURL(allowed) == normalizedHTU {
			return true
		}
	}
	return false
}

// isPublicClient checks whether the client is a public client by inspecting
// the token endpoint authentication method. Clients using "none" or
// "attest_jwt_client_auth" are treated as public for DPoP refresh token
// binding purposes.
func isPublicClient(client fosite.Client) bool {
	oidcClient, ok := client.(fosite.OpenIDConnectClient)
	if !ok {
		// If the client doesn't implement OpenIDConnectClient, fall back
		// to the IsPublic() method on the base Client interface.
		return client.IsPublic()
	}
	method := oidcClient.GetTokenEndpointAuthMethod()
	return method == "none" || method == "attest_jwt_client_auth"
}
