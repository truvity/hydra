#!/usr/bin/env bash
#
# Generate a Client Attester key bundle for HAIP conformance testing:
#
#   attester-keys/
#     ca.key.pem                 # root CA private key
#     ca.cert.pem                # root CA certificate (paste into hydra config)
#     leaf.key.pem               # leaf (attester signing) private key
#     leaf.cert.pem              # leaf certificate signed by the root
#     attester-keys.jwks.json    # JWKS with one ES256 private key + x5c chain
#                                # → give this to the conformance test
#
# The JWKS uses ES256 (P-256). Each key entry carries:
#   - the private key material (d, x, y, crv)
#   - an x5c header with [leaf_DER_base64, root_DER_base64] (RFC 7517 §4.7)
#
# Requirements: openssl (>=1.1.1), jq.
#
# Usage:
#   ./gen-attester-jwks.sh                  # writes to ./attester-keys
#   OUT=/tmp/haip ./gen-attester-jwks.sh    # override output directory
#   SUBJECT=my-wallet ./gen-attester-jwks.sh
#
# After running:
#   1. Copy ca.cert.pem content into hydra config:
#        wallet_attestation:
#          enabled: true
#          trust_anchors:
#            - |
#              -----BEGIN CERTIFICATE-----
#              …
#              -----END CERTIFICATE-----
#   2. Upload attester-keys.jwks.json in the conformance test.

set -euo pipefail

OUT="${OUT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)/attester-keys}"
SUBJECT="${SUBJECT:-haip-wallet-attester}"
DAYS="${DAYS:-3650}"

for cmd in openssl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "error: '$cmd' is required" >&2
    exit 1
  fi
done

mkdir -p "$OUT"
cd "$OUT"

# --- 1. Root CA --------------------------------------------------------------
if [[ ! -f ca.key.pem ]]; then
  echo "==> generating root CA key + self-signed cert"
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key.pem
  openssl req -x509 -new -key ca.key.pem -days "$DAYS" \
    -subj "/CN=${SUBJECT}-root-ca" \
    -out ca.cert.pem
else
  echo "==> reusing existing ca.key.pem / ca.cert.pem"
fi

# --- 2. Leaf (attester signing) ----------------------------------------------
if [[ ! -f leaf.key.pem ]]; then
  echo "==> generating leaf key + CSR"
  openssl ecparam -name prime256v1 -genkey -noout -out leaf.key.pem
  openssl req -new -key leaf.key.pem \
    -subj "/CN=${SUBJECT}" \
    -out leaf.csr.pem

  echo "==> signing leaf with root CA"
  openssl x509 -req -in leaf.csr.pem \
    -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial \
    -days "$DAYS" \
    -out leaf.cert.pem
  rm -f leaf.csr.pem ca.srl
else
  echo "==> reusing existing leaf.key.pem / leaf.cert.pem"
fi

# --- 3. JWKS with x5c ---------------------------------------------------------
echo "==> building JWKS with x5c chain"

# EC private key (PEM → JWK coordinates) via jose-util style extraction.
# `openssl ec` dumps the raw key; parse hex d, and pub-point x||y.
PRIV_D_HEX=$(openssl ec -in leaf.key.pem -noout -text 2>/dev/null \
  | sed -n '/priv:/,/pub:/p' | sed -e '/priv:/d' -e '/pub:/d' \
  | tr -d ' :\n')
PUB_HEX=$(openssl ec -in leaf.key.pem -noout -text 2>/dev/null \
  | sed -n '/pub:/,/ASN1 OID/p' | sed -e '/pub:/d' -e '/ASN1 OID/d' \
  | tr -d ' :\n')

# Uncompressed point: 04 || X (32) || Y (32) — 65 bytes / 130 hex chars.
if [[ ${#PUB_HEX} -ne 130 ]] || [[ "${PUB_HEX:0:2}" != "04" ]]; then
  echo "error: unexpected EC public-key layout (len=${#PUB_HEX})" >&2
  exit 1
fi
X_HEX="${PUB_HEX:2:64}"
Y_HEX="${PUB_HEX:66:64}"

# Some keys emit d with a leading 00 byte if the MSB of d is set; strip it so
# the base64url value is always 32 bytes.
if [[ ${#PRIV_D_HEX} -eq 66 && "${PRIV_D_HEX:0:2}" == "00" ]]; then
  PRIV_D_HEX="${PRIV_D_HEX:2}"
fi

# Helpers ---------------------------------------------------------------------
hex_to_b64url() {
  # hex → raw bytes → base64url (no padding)
  printf '%s' "$1" | xxd -r -p | base64 | tr -d '=\n' | tr '/+' '_-'
}

pem_to_der_b64() {
  # Strip PEM headers, keep standard base64 (the `x5c` array is standard base64
  # per RFC 7517, NOT base64url).
  grep -v -E '^-----' "$1" | tr -d '\n'
}

X_B64=$(hex_to_b64url "$X_HEX")
Y_B64=$(hex_to_b64url "$Y_HEX")
D_B64=$(hex_to_b64url "$PRIV_D_HEX")

LEAF_DER_B64=$(pem_to_der_b64 leaf.cert.pem)

KID="${SUBJECT}-$(date -u +%Y%m%d)"

# x5c MUST NOT include the trust anchor per draft-ietf-oauth-attestation-based-
# client-auth §6 and HAIP §5.5. The root CA is pre-configured on the AS as a
# trust anchor; repeating it in x5c is a hard rejection by compliant
# verifiers. For a simple 2-level PKI (root → leaf) the chain contains just
# the leaf.
jq -n \
  --arg kid "$KID" \
  --arg x "$X_B64" \
  --arg y "$Y_B64" \
  --arg d "$D_B64" \
  --arg leaf "$LEAF_DER_B64" \
  '{
     keys: [{
       kty: "EC",
       crv: "P-256",
       alg: "ES256",
       use: "sig",
       kid: $kid,
       x:   $x,
       y:   $y,
       d:   $d,
       x5c: [ $leaf ]
     }]
   }' > attester-keys.jwks.json

# Public-only copy (drop "d") for anyone who just needs to distribute the JWKS.
jq '.keys[0] |= (del(.d))' attester-keys.jwks.json > attester-keys.public.jwks.json

# --- 4. Summary ---------------------------------------------------------------
echo
echo "==> artifacts in: $OUT"
ls -1 .

echo
echo "==> paste this into hydra config under wallet_attestation.trust_anchors:"
echo "---8<---"
cat ca.cert.pem
echo "---8<---"
