#!/bin/bash

echo "USING VASYAN OPENSSL"

LD_PRELOAD=/home/alisa/Projects/openssl-gost-build/build/lib/libssl.so.1.1:\
/home/alisa/Projects/openssl-gost-build/build/lib/libcrypto.so.1.1 \
OPENSSL_CONF=/home/alisa/Projects/openssl-gost-build/openssl-gost.conf \
/home/alisa/Projects/openssl-gost-build/build/bin/openssl $@
