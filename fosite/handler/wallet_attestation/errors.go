// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package wallet_attestation

import (
	"net/http"

	"github.com/ory/hydra/v2/fosite"
)

// ErrInvalidWalletAttestation is the base error for all Wallet Attestation validation failures.
// Uses "invalid_client" per OAuth 2.0 convention for client authentication errors.
// Context is added via .WithHint() and .WithDebugf() at each call site.
var ErrInvalidWalletAttestation = &fosite.RFC6749Error{
	ErrorField:       "invalid_client",
	CodeField:        http.StatusUnauthorized,
	DescriptionField: "The wallet attestation is invalid.",
}

// ErrInvalidClientAttestation MAY be used as an alternative to invalid_client when the AS
// wants to provide more specific error information about attestation validation failures
// per draft-ietf-oauth-attestation-based-client-auth-07 §6.2.
var ErrInvalidClientAttestation = &fosite.RFC6749Error{
	ErrorField:       "invalid_client_attestation",
	CodeField:        http.StatusUnauthorized,
	DescriptionField: "The client attestation could not be verified.",
}
