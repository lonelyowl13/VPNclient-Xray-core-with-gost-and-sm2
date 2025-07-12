#!/bin/bash

# Generate GOST2012-512 certificate
./xray tls cert --algorithm=gost2012_512 --domain=example.com --name="Test Server GOST2012-512" --org="Test Organization" --file=test_cert_gost2012_512



