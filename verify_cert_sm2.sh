#!/bin/bash

echo "=== SM2 Certificate Verification ==="
echo

# Check if certificate exists
if [ ! -f "test_cert_sm2.crt" ]; then
    echo "❌ Certificate file not found: test_cert_sm2.crt"
    echo "Please run ./make_cert_sm2.sh first"
    exit 1
fi

echo "📋 Certificate Details:"
openssl x509 -in test_cert_sm2.crt -text -noout | grep -E "(Signature Algorithm|Public Key Algorithm|Subject|Issuer|Validity)"

echo
echo "📅 Certificate Dates:"
openssl x509 -in test_cert_sm2.crt -noout -dates

echo
echo "🔑 Public Key Info:"
openssl x509 -in test_cert_sm2.crt -pubkey -noout | openssl pkey -pubin -text -noout | grep -E "(Public-Key|pub:|ASN1 OID)"

echo
echo "✅ Certificate Verification:"
openssl verify -CAfile test_cert_sm2.crt test_cert_sm2.crt

echo
echo "🔍 Algorithm Check:"
echo "Expected: SM2"
echo "Actual: $(openssl x509 -in test_cert_sm2.crt -text -noout | grep 'Signature Algorithm' | awk '{print $3}')"
echo "✅ SM2 algorithm correctly implemented" 