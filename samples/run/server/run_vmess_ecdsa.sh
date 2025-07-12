#!/bin/bash

echo "=== VMess Server with ECDSA Certificate ==="
echo

# Check if certificate exists, if not create it
if [ ! -f "test_cert_ecdsa.crt" ] || [ ! -f "test_cert_ecdsa.key" ]; then
    echo "📝 Creating ECDSA certificate..."
    ./xray tls cert --algorithm=ecdsa --domain=example.com --name="Test Server ECDSA" --org="Test Organization" --file=test_cert_ecdsa > /dev/null 2>&1
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
echo "🔧 Creating VMess server configuration..."

# Create VMess server configuration
cat > vmess_ecdsa.json << 'EOF'
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
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "test_cert_ecdsa.crt",
              "keyFile": "test_cert_ecdsa.key"
            }
          ]
        }
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

echo "✅ Configuration file created: vmess_ecdsa.json"
echo
echo "🚀 Starting VMess server with ECDSA certificate..."
echo "📋 Server details:"
echo "   - Port: 443"
echo "   - Protocol: VMess"
echo "   - Security: TLS with ECDSA certificate"
echo "   - Client ID: b831381d-6324-4d53-ad4f-8cda48b30811"
echo
echo "Press Ctrl+C to stop the server"
echo

# Start the server
./xray -c vmess_ecdsa.json 