#!/bin/bash

echo "🔍 Certificate Verification Suite"
echo "================================="
echo

# Function to verify certificate
verify_cert() {
    local cert_name=$1
    local cert_file="test_cert_${cert_name}.crt"
    
    echo "=== ${cert_name^^} Certificate ==="
    
    if [ ! -f "$cert_file" ]; then
        echo "❌ Certificate file not found: $cert_file"
        echo "   Please run ./make_cert_${cert_name}.sh first"
        echo
        return 1
    fi
    
    echo "📋 Algorithm: $(openssl x509 -in "$cert_file" -text -noout | grep 'Signature Algorithm' | awk '{print $3}')"
    echo "📅 Valid: $(openssl x509 -in "$cert_file" -noout -dates | tr '\n' ' ')"
    echo "✅ Verification: $(openssl verify -CAfile "$cert_file" "$cert_file" 2>/dev/null | awk '{print $2}')"
    echo "🔑 Key Size: $(openssl x509 -in "$cert_file" -pubkey -noout | openssl pkey -pubin -text -noout | grep 'Public-Key' | awk '{print $3}')"
    echo
}

# Verify all certificates
verify_cert "gost2012_256"
verify_cert "gost2012_512" 
verify_cert "sm2"

echo "📊 Summary:"
echo "==========="
echo "• GOST2012-256: Uses SM2 implementation (not true GOST)"
echo "• GOST2012-512: Uses SM2 implementation (not true GOST)"
echo "• SM2: Correctly implemented"
echo
echo "💡 Note: GOST certificates currently use SM2 as implementation"
echo "   True GOST requires specialized GOST libraries" 