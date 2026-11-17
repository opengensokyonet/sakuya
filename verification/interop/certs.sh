#!/usr/bin/env bash
# Generates the test certificates of an interop run: a root CA (`ca.pem`)
# and a leaf certificate for the names `server`, `server4`, `server6` and
# `server46` (`cert.pem`, with its key in `priv.key`), a chain of length 1.
#
# Usage: certs.sh <output directory>
#
# Derived from certs.sh and cert_config.txt of the QUIC interop runner
# (https://github.com/quic-interop/quic-interop-runner), which is licensed
# under the Apache License 2.0; the longer chains the runner makes for its
# amplification test are left out. The certificates are valid for ten days
# and are for tests only.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <output directory>" >&2
  exit 2
fi
dir=$1
mkdir -p "$dir"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat >"$work/cert_config.txt" <<'CONF'
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
dirstring_type = nobmp
[ req_distinguished_name ]
[ v3_ca ]
keyUsage=critical, keyCertSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints=critical,CA:TRUE,pathlen:100
CONF

# Root CA.
openssl ecparam -name prime256v1 -genkey -out "$work/ca.key"
openssl req -x509 -sha256 -nodes -days 10 -key "$work/ca.key" \
  -out "$work/ca.pem" \
  -subj "/O=interop runner Root Certificate Authority/" \
  -config "$work/cert_config.txt" -extensions v3_ca 2>/dev/null

# Leaf certificate, signed by the root.
openssl ecparam -name prime256v1 -genkey -out "$work/leaf.key"
openssl req -new -key "$work/leaf.key" -nodes -out "$work/leaf.csr" \
  -subj "/O=interop runner leaf/" 2>/dev/null
openssl x509 -req -sha256 -days 10 -in "$work/leaf.csr" -out "$work/leaf.pem" \
  -CA "$work/ca.pem" -CAkey "$work/ca.key" -CAcreateserial \
  -extfile <(printf "subjectAltName=DNS:server,DNS:server4,DNS:server6,DNS:server46") \
  2>/dev/null

cp "$work/ca.pem" "$dir/ca.pem"
cp "$work/leaf.pem" "$dir/cert.pem"
cp "$work/leaf.key" "$dir/priv.key"
chmod a+r "$dir/ca.pem" "$dir/cert.pem" "$dir/priv.key"
