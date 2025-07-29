#!/bin/bash

echo "=== VMess Server with GOST2012-512 Certificate ==="
echo

# Check if certificate exists, if not create it
if [ ! -f "test_cert_gost2012_512.crt" ] || [ ! -f "test_cert_gost2012_512.key" ]; then
    echo "📝 Creating GOST2012-512 certificate..."
    ./make_cert_gost2012_512.sh > /dev/null 2>&1
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
cat > vmess_gost2012_512.json << 'EOF'
{
  "log": {
    "loglevel": "debug"
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
              "certificateFile": "test_cert_gost2012_512.crt",
              "keyFile": "test_cert_gost2012_512.key",
              "certificateType": "gost2012_512"
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

echo "✅ Configuration file created: vmess_gost2012_512.json"
echo
echo "🚀 Starting VMess server with GOST2012-512 certificate..."
echo "📋 Server details:"
echo "   - Port: 443"
echo "   - Protocol: VMess"
echo "   - Security: TLS with GOST2012-512 certificate"
echo "   - Client ID: b831381d-6324-4d53-ad4f-8cda48b30811"
echo
echo "Press Ctrl+C to stop the server"
echo

# Start the server
./xray -c vmess_gost2012_512.json 