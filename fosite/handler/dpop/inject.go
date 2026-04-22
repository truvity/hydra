// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"net/http"
	"net/url"
)

// contextKey is an unexported type for context keys defined in this package,
// preventing collisions with keys defined in other packages.
type contextKey string

// DPoPNonceContextKey is the context key used to deliver the DPoP-Nonce value
// between the DPoP handler and the endpoint handler. The endpoint handler
// stores a *string in the context before calling Fosite, and the DPoP handler
// writes the nonce value to it. After the Fosite call returns, the endpoint
// handler reads the value and sets the DPoP-Nonce HTTP response header.
const DPoPNonceContextKey contextKey = "dpop_nonce"

// InjectDPoPHeader extracts the DPoP HTTP header and injects it into the
// request form for consumption by the DPoP handler. This bridges the gap
// between the raw HTTP request (available at the endpoint handler level) and
// the Fosite handler which only sees the parsed form via AccessRequester.
//
// If multiple DPoP header values are present, the function sets
// dpop_proof_error=multiple_headers so the handler can reject per §4.3 check 1.
// If exactly one value is present, it is set as dpop_proof.
// If no DPoP header is present, the form is left unchanged.
func InjectDPoPHeader(r *http.Request) {
	dpopValues := r.Header.Values("DPoP")
	if len(dpopValues) == 0 {
		return
	}
	// Ensure the form is parsed before injecting.
	if r.PostForm == nil {
		_ = r.ParseForm()
	}
	if r.PostForm == nil {
		r.PostForm = make(url.Values)
	}
	if len(dpopValues) > 1 {
		r.PostForm.Set("dpop_proof_error", "multiple_headers")
	} else {
		r.PostForm.Set("dpop_proof", dpopValues[0])
	}
}
