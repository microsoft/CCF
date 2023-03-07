# Based on https://hub.docker.com/_/golang/

# To run this:
#   docker build -t attestation-container . [--build-arg variant=dev]
#   docker run -it --rm attestation-container

# Two variants: run (production) or dev (development)
ARG variant=run

# Build
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.20-fips-cbl-mariner2.0 AS builder-app
WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY . .
RUN go mod download && go mod verify

# Note: Use CGO_ENABLED=0 to build statically-linked binaries deployable in scratch image
RUN CGO_ENABLED=0 go build -v -o /usr/local/bin/app .

FROM builder-app AS builder-test
WORKDIR /usr/src/app
## Pre-compile tests to avoid I/O errors in ACI
RUN CGO_ENABLED=0 go test -c && cd attest && CGO_ENABLED=0 go test -c && cd ../uvm && CGO_ENABLED=0 go test -c

# Run
FROM mcr.microsoft.com/cbl-mariner/distroless/minimal:2.0 AS app-run
COPY --from=builder-app /usr/local/bin/app /usr/local/bin/app

FROM app-run AS app-dev
COPY --from=builder-test /usr/src/app/attestation-container.test* /usr/local/bin/attestation-container.test 
COPY --from=builder-test /usr/src/app/attest/attest.test* /usr/local/bin/attest.test 
COPY --from=builder-test /usr/src/app/attest/testdata/host_amd_certificate_env* /testdata/
COPY --from=builder-test /usr/src/app/uvm/uvm.test* /usr/local/bin/uvm.test 

# Final 
FROM app-${variant} AS final
CMD ["app"]
