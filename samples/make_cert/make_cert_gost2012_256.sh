#!/bin/bash

mkdir -p certs

# Generate GOST2012_256 certificate
../../xray tls cert --algorithm=gost2012_256 --domain=example.com --name="Test Server GOST2012_256" --org="Test Organization" --file=certs/test_cert_gost2012_256 