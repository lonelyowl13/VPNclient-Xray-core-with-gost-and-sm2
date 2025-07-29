#!/bin/bash

echo "=== VLESS Client with SM2 Certificate ==="
echo

echo "🔧 Starting VLESS client..."
echo "📋 Client details:"
echo "   - Port: 1080 (SOCKS)"
echo "   - Protocol: VLESS"
echo "   - Server: 127.0.0.1:443"
echo "   - Security: TLS with SM2 certificate"
echo
echo "Press Ctrl+C to stop the client"
echo

# Start the client
./xray -c ../configs/client/vless_client_sm2.json 