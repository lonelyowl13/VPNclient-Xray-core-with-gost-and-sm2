#!/bin/bash

mkdir -p ../certs

# Generate SM2 certificate
../../xray tls cert --algorithm=sm2 --domain=example.com --name="Test Server SM2" --org="Test Organization" --file=../certs/test_cert_sm2 