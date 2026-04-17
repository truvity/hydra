// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package preauth

// Pre-Authorized Code error handling follows the pattern established by Spec 1 (RAR) and
// Spec 2 (DPoP): the handler reuses fosite.ErrInvalidGrant and fosite.ErrInvalidRequest
// with .WithHint() at each call site. No new error code constants are needed — OIDC4VCI §6.3
// uses standard OAuth 2.0 error codes for pre-authorized code errors.
//
// Error codes and hints used by the PreAuth handler:
//
// invalid_request:
//   - "pre-authorized_code parameter is required"
//   - "tx_code required but not provided"
//   - "tx_code provided but not expected"
//   - "requested credential_configuration_id not authorized"
//   - "authorization_details must be a non-empty array"
//
// invalid_grant:
//   - "pre-authorized code not found"
//   - "pre-authorized code already redeemed"
//   - "pre-authorized code expired"
//   - "tx_code does not match"
//   - "client_id mismatch"
