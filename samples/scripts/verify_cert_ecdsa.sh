#!/bin/bash

echo "=== Проверка ECDSA сертификата ==="

if [ ! -f "../certs/test_cert_ecdsa.crt" ]; then
    echo "❌ Файл ../certs/test_cert_ecdsa.crt не найден"
    exit 1
fi

if [ ! -f "../certs/test_cert_ecdsa.key" ]; then
    echo "❌ Файл ../certs/test_cert_ecdsa.key не найден"
    exit 1
fi

echo "✅ Файлы сертификата найдены"

openssl x509 -in ../certs/test_cert_ecdsa.crt -text -noout

# Проверка формата сертификата
if openssl x509 -in ../certs/test_cert_ecdsa.crt -text -noout > /dev/null 2>&1; then
    echo "✅ Формат сертификата корректный"
else
    echo "❌ Ошибка в формате сертификата"
    exit 1
fi

# Проверка алгоритма
ALGORITHM=$(openssl x509 -in ../certs/test_cert_ecdsa.crt -text -noout | grep "Public Key Algorithm" | head -1)
echo "📋 Алгоритм: $ALGORITHM"

# Проверка срока действия
if openssl x509 -in ../certs/test_cert_ecdsa.crt -checkend 0 -noout > /dev/null 2>&1; then
    echo "✅ Сертификат не истек"
else
    echo "❌ Сертификат истек"
    exit 1
fi

echo "✅ ECDSA сертификат прошел все проверки" 