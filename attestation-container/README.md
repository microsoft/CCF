# Attestation Container

This is a gRPC server application to fetch SEV-SNP attestation and its endorsement.

## Environment

This application needs to run on [SEV-SNP VM](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf).

## Dependencies

- [Go](https://go.dev/doc/install)
- [gRPC](https://grpc.io/docs/languages/go/quickstart/)

## How to start the app

The following command starts the gRPC server application.

```bash
# In the same directory as this README.md
go run .
```

## Test

Unit test:

```bash
cd attest
go test
```

E2E test:

```bash
# Run the app first
go run .

# In another terminal
go test
```

## Update protobuf

When you edit `.proto` file, you also need to update `.pb.go` files by:

```bash
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative protobuf/attestation-container.proto
```
