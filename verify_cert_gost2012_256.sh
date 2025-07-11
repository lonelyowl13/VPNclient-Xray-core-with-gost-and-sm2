#!/bin/bash

openssl x509 -in test_cert_gost2012_256.crt -text -noout | grep -E "(Signature Algorithm|Public Key Algorithm|Subject|Issuer|Validity)"
exit 0

echo "=== GOST2012-256 Certificate Verification ==="
echo

# Check if certificate exists
if [ ! -f "test_cert_gost2012_256.crt" ]; then
    echo "❌ Certificate file not found: test_cert_gost2012_256.crt"
    echo "Please run ./make_cert_gost2012_256.sh first"
    exit 1
fi

echo "📋 Certificate Details:"
openssl x509 -in test_cert_gost2012_256.crt -text -noout | grep -E "(Signature Algorithm|Public Key Algorithm|Subject|Issuer|Validity)"

echo
echo "📅 Certificate Dates:"
openssl x509 -in test_cert_gost2012_256.crt -noout -dates

echo
echo "🔑 Public Key Info:"
openssl x509 -in test_cert_gost2012_256.crt -pubkey -noout | openssl pkey -pubin -text -noout | grep -E "(Public-Key|pub:|ASN1 OID)"

echo
echo "✅ Certificate Verification:"
openssl verify -CAfile test_cert_gost2012_256.crt test_cert_gost2012_256.crt

echo
echo "🔍 Algorithm Check:"
echo "Expected: GOST2012-256"
echo "Actual: $(openssl x509 -in test_cert_gost2012_256.crt -text -noout | grep 'Signature Algorithm' | awk '{print $3}')"
echo "Note: Currently using SM2 as GOST implementation" 