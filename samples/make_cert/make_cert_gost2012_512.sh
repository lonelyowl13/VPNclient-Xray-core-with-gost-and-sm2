#!/bin/bash

mkdir -p ../certs

# Generate GOST2012_512 certificate
../../xray tls cert --algorithm=gost2012_512 --domain=example.com --name="Test Server GOST2012_512" --org="Test Organization" --file=../certs/test_cert_gost2012_512



