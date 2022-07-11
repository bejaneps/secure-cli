# Secure CLI

A tool to encrypt/decrypt message using RSA technique

## Dependencies

Download and install latest Go version from https://go.dev/dl

## Usage

Using `make` if available

```bash
make build
./secure-cli --help
```

Using Go's SDK

```bash
go build -o ./secure-cli ./cmd/cli/main.go
./secure-cli --help

# or
go run cmd/cli/main.go --help
```

## Scripts

You can use `gen.sh` script to generate pair of public/private key files