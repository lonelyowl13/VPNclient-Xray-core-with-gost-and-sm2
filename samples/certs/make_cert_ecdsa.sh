#!/bin/bash
set -e

CERT_NAME="test_cert_ecdsa"

openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_NAME.key"
openssl req -new -x509 -key "$CERT_NAME.key" -out "$CERT_NAME.crt" -days 365 \
    -subj "/C=RU/ST=Test/L=Test/O=Test/OU=Test/CN=localhost"

chmod 600 "$CERT_NAME.key"
chmod 644 "$CERT_NAME.crt"
echo "ECDSA сертификат сгенерирован: $CERT_NAME.crt, $CERT_NAME.key" 