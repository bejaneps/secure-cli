#!/bin/sh

# not supported in Go yet
gen_rsa_pkcs8_key() {
  # generate private key
  openssl genpkey -out private.pem -algorithm RSA -des3 -pass pass:"$(LC_ALL=C tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 13 | tee passphrase.txt)" -pkeyopt rsa_keygen_bits:2048

  # convert generated private key to pkcs8 v2 format
  openssl pkcs8 -nocrypt -in private.pem -out private-pkcs8.pem -passout pass:"$(LC_ALL=C tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 13 | tee passphrase.txt)" -v2 des3

  # generate public key from a private key
  openssl rsa -in private.pem -outform PEM -pubout -out public.pem -passin pass:"$(cat passphrase.txt)"
}

gen_rsa_key() {
  openssl genrsa -aes256 -out private.pem -passout pass:"$(LC_ALL=C tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 13 | tee passphrase.txt)" 2048

  # generate public key from a private key
  openssl rsa -in private.pem -outform PEM -pubout -out public.pem -passin pass:"$(cat passphrase.txt)"
}

gen_rsa_key