#!/bin/bash

echo "=== Проверка всех сертификатов ==="
echo

cd "$(dirname "$0")"

echo "🔍 Проверяю SM2 сертификат..."
./verify_cert_sm2.sh
echo

echo "🔍 Проверяю GOST2012_256 сертификат..."
./verify_cert_gost2012_256.sh
echo

echo "🔍 Проверяю GOST2012_512 сертификат..."
./verify_cert_gost2012_512.sh
echo

echo "🔍 Проверяю ECDSA сертификат..."
./verify_cert_ecdsa.sh
echo

echo "✅ Все сертификаты проверены" 