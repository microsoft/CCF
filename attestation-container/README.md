# Attestation Container

This is a gRPC server application to fetch SEV-SNP attestation and its endorsement.

## Environment

This application needs to run on [SEV-SNP VM](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf).

## Dependencies

- [Go](https://go.dev/doc/install)
- [gRPC](https://grpc.io/docs/languages/go/quickstart/)

## How to start the app

The following command starts the gRPC server application (must be inside SEV-SNP VM).

```bash
# In the same directory as this README.md
go run .
```

You can use insecure virtual mode to run the application on non SEV-SNP VM.
(**It't not secure. Do not use it in production**).

```bash
go run . --insecure-virtual
```

You can find the details of the flag and other flags by running `go run . --help`.

## Build

Since it's a go application, you can build the application before running it.

```bash
go build
./attestation-container
```

## API

The gPRC API is defined in [attestation-container.proto](https://github.com/microsoft/CCF/blob/main/attestation-container/protobuf/attestation-container.proto).

Note that gPRC communication is used over [Unix domain sockets (UDS)](https://en.wikipedia.org/wiki/Unix_domain_socket). You can find an example client code in [the E2E test](https://github.com/microsoft/CCF/blob/main/attestation-container/attestation-container_test.go).

## Test

Unit test:

```bash
cd attest
go test # Test for attest package

cd ../uvm
go test # Test for uvm package
```

E2E test:

```bash
# Run the app first
go run .

# In another terminal
go test
```

## Development and maintenance

### Update protobuf

When you edit `.proto` file, you also need to update `.pb.go` files by:

```bash
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative protobuf/attestation-container.proto
```

### Upgrade dependencies

PRs to upgrade the dependencies are created automatically by [Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot) (The setting is done [here](https://github.com/microsoft/CCF/blob/main/.github/dependabot.yml)).

However, when Dependabot creates multiple PRs at the same time, go.mod file can be corrupted.
In that case, you still need to fix go.mod using `go` command manually.

```bash
go get -u
go mod tidy
```
