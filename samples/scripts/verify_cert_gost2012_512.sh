#!/bin/bash

echo "=== Проверка GOST2012_512 сертификата ==="

if [ ! -f "../certs/test_cert_gost2012_512.crt" ]; then
    echo "❌ Файл ../certs/test_cert_gost2012_512.crt не найден"
    exit 1
fi

if [ ! -f "../certs/test_cert_gost2012_512.key" ]; then
    echo "❌ Файл ../certs/test_cert_gost2012_512.key не найден"
    exit 1
fi

echo "✅ Файлы сертификата найдены"


# Проверка формата сертификата
if openssl x509 -in ../certs/test_cert_gost2012_512.crt -text -noout > /dev/null 2>&1; then
    echo "✅ Формат сертификата корректный"
else
    echo "❌ Ошибка в формате сертификата"
    exit 1
fi

#openssl x509 -in ../certs/test_cert_gost2012_512.crt -text -noout
# Проверка алгоритма
ALGORITHM=$(openssl x509 -in ../certs/test_cert_gost2012_512.crt -text -noout | grep "Public Key Algorithm" | head -1)
echo "📋 Алгоритм: $ALGORITHM"

# Проверка срока действия
if openssl x509 -in ../certs/test_cert_gost2012_512.crt -checkend 0 -noout > /dev/null 2>&1; then
    echo "✅ Сертификат не истек"
else
    echo "❌ Сертификат истек"
    exit 1
fi

echo "✅ GOST2012_512 сертификат прошел все проверки" 