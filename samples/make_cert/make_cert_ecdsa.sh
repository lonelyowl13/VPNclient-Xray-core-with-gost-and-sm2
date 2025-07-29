#!/bin/bash

mkdir -p certs

# Generate ECDSA certificate
../../xray tls cert --algorithm=ecdsa --domain=example.com --name="Test Server ECDSA" --org="Test Organization" --file=../certs/test_cert_ecdsa 