#!/bin/bash

set -e

CERT_FILE="test_cert_rsa.crt"
KEY_FILE="test_cert_rsa.key"
CONFIG_FILE="vmess_rsa.json"
DOMAIN="localhost"
ORG="Test Organization"
CLIENT_ID="b831381d-6324-4d53-ad4f-8cda48b30811"

# 1. Генерация RSA сертификата, если его нет
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "📝 Generating RSA certificate..."
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 365 -nodes \
        -subj "/CN=$DOMAIN/O=$ORG"
    echo "✅ RSA certificate generated."
else
    echo "✅ RSA certificate already exists."
fi

echo
# 2. Создание VMess server config
cat > "$CONFIG_FILE" << EOF
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
            "id": "$CLIENT_ID",
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
              "certificateFile": "$CERT_FILE",
              "keyFile": "$KEY_FILE"
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

echo "✅ Configuration file created: $CONFIG_FILE"
echo
# 3. Запуск Xray

echo "🚀 Starting VMess server with RSA certificate..."
echo "📋 Server details:"
echo "   - Port: 443"
echo "   - Protocol: VMess"
echo "   - Security: TLS with RSA certificate"
echo "   - Client ID: $CLIENT_ID"
echo
echo "Press Ctrl+C to stop the server"
echo

./xray -c "$CONFIG_FILE" 