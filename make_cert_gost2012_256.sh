#!/bin/bash

# Generate GOST2012-256 certificate
./xray tls cert --algorithm=gost2012_256 --domain=example.com --name="Test Server GOST2012-256" --org="Test Organization" --file=test_cert_gost2012_256 