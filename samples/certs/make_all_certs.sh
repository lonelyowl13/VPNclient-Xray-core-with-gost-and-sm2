#!/bin/bash
set -e

cd "$(dirname "$0")"

./make_cert_sm2.sh
./make_cert_gost2012_256.sh
./make_cert_gost2012_512.sh
./make_cert_ecdsa.sh

echo "\nВсе сертификаты сгенерированы." 