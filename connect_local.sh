#!/bin/bash

echo "openssl s_client -connect 127.0.0.1:443 -servername example.com "
openssl s_client -connect 127.0.0.1:443 -servername example.com
