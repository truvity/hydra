// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rar

import (
	"net/http"

	"github.com/ory/hydra/v2/fosite"
)

// ErrInvalidAuthorizationDetails is returned when the authorization_details parameter
// is invalid per RFC 9396 §5. Context is added via .WithHint() and .WithDebugf() at
// each call site.
var ErrInvalidAuthorizationDetails = &fosite.RFC6749Error{
	DescriptionField: "The authorization_details parameter is invalid.",
	ErrorField:       "invalid_authorization_details",
	CodeField:        http.StatusBadRequest,
}
