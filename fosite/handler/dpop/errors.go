// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"net/http"

	"github.com/ory/hydra/v2/fosite"
)

// ErrInvalidDPoPProof is returned when a DPoP proof JWT fails validation
// per RFC 9449 §4.3. Context is added via .WithHint() and .WithDebugf() at
// each call site.
var ErrInvalidDPoPProof = &fosite.RFC6749Error{
	DescriptionField: "The DPoP proof is invalid.",
	ErrorField:       "invalid_dpop_proof",
	CodeField:        http.StatusBadRequest,
}

// ErrUseDPoPNonce is returned when the authorization server requires a nonce
// in the DPoP proof per RFC 9449 §8. The error response includes a DPoP-Nonce
// header with a fresh nonce value.
var ErrUseDPoPNonce = &fosite.RFC6749Error{
	DescriptionField: "Authorization server requires nonce in DPoP proof.",
	ErrorField:       "use_dpop_nonce",
	CodeField:        http.StatusBadRequest,
}
