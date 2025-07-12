#!/bin/bash

echo "=== Проверка SM2 сертификата ==="

if [ ! -f "test_cert_sm2.crt" ]; then
    echo "❌ Файл test_cert_sm2.crt не найден"
    exit 1
fi

if [ ! -f "test_cert_sm2.key" ]; then
    echo "❌ Файл test_cert_sm2.key не найден"
    exit 1
fi

echo "✅ Файлы сертификата найдены"

# Проверка формата сертификата
if openssl x509 -in test_cert_sm2.crt -text -noout > /dev/null 2>&1; then
    echo "✅ Формат сертификата корректный"
else
    echo "❌ Ошибка в формате сертификата"
    exit 1
fi

# Проверка алгоритма
ALGORITHM=$(openssl x509 -in test_cert_sm2.crt -text -noout | grep "Public Key Algorithm" | head -1)
echo "📋 Алгоритм: $ALGORITHM"

# Проверка срока действия
if openssl x509 -in test_cert_sm2.crt -checkend 0 -noout > /dev/null 2>&1; then
    echo "✅ Сертификат не истек"
else
    echo "❌ Сертификат истек"
    exit 1
fi

echo "✅ SM2 сертификат прошел все проверки" 