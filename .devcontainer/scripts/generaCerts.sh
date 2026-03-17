#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../testdata/certs"

generate_set() {
  DAYS=$1

  PEM_DIR="$BASE_DIR/${DAYS}d-pem"
  PFX_DIR="$BASE_DIR/${DAYS}d-pfx"

  mkdir -p "$PEM_DIR" "$PFX_DIR"

  echo "Generating $DAYS-day certificate set..."

  # 1. Private key
  openssl genrsa -out "$PEM_DIR/key.pem" 2048

  # 2. CSR
  openssl req -new \
    -key "$PEM_DIR/key.pem" \
    -out "$PEM_DIR/csr.pem" \
    -subj "/C=ES/ST=Madrid/L=Madrid/O=Test/OU=TestPReprod/CN=localhost"

  # 3. Self-signed cert (simulating CA)
  openssl x509 -req \
    -in "$PEM_DIR/csr.pem" \
    -signkey "$PEM_DIR/key.pem" \
    -out "$PEM_DIR/cert.pem" \
    -days "$DAYS" \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

  # 4. Chain (simulación: en real vendría de la CA)
  cp "$PEM_DIR/cert.pem" "$PEM_DIR/chain.pem"

  # 5. Fullchain = cert + chain
  cat "$PEM_DIR/cert.pem" "$PEM_DIR/chain.pem" > "$PEM_DIR/fullchain.pem"

  # 6. PFX (PKCS#12)
  openssl pkcs12 -export \
    -out "$PFX_DIR/keystore.p12" \
    -inkey "$PEM_DIR/key.pem" \
    -in "$PEM_DIR/cert.pem" \
    -certfile "$PEM_DIR/chain.pem" \
    -name "test-cert-$DAYS" \
    -passout pass:mipassword

  # cleanup
  rm "$PEM_DIR/csr.pem"

  echo "Done $DAYS days"
}

# Clean previous
rm -rf "$BASE_DIR"
mkdir -p "$BASE_DIR"

generate_set 180
generate_set 360

echo "All certificates generated."
