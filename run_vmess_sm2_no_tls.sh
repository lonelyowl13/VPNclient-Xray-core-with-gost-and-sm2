#!/bin/bash

echo "=== VMess Server with SM2 Certificate (No TLS) ==="
echo

# Check if certificate exists, if not create it
if [ ! -f "test_cert_sm2.crt" ] || [ ! -f "test_cert_sm2.key" ]; then
    echo "📝 Creating SM2 certificate..."
    ./make_cert_sm2.sh > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✅ Certificate created successfully"
    else
        echo "❌ Failed to create certificate"
        exit 1
    fi
else
    echo "✅ Certificate already exists"
fi

echo
echo "🔧 Creating VMess server configuration (No TLS)..."

# Create VMess server configuration without TLS
cat > vmess_sm2_no_tls.json << 'EOF'
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

echo "✅ Configuration file created: vmess_sm2_no_tls.json"
echo
echo "🚀 Starting VMess server without TLS..."
echo "📋 Server details:"
echo "   - Port: 443"
echo "   - Protocol: VMess"
echo "   - Security: None (no TLS)"
echo "   - Client ID: b831381d-6324-4d53-ad4f-8cda48b30811"
echo
echo "Press Ctrl+C to stop the server"
echo

# Start the server
./xray -c vmess_sm2_no_tls.json 