# Based on https://hub.docker.com/_/golang/

# To run this:
#   docker build -t attestation-container . [--build-arg build_test=True]
#   docker run -it --rm attestation-container

## Build
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.20-fips-cbl-mariner2.0 as builder
ARG build_test=False

WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Note: Use CGO_ENABLED=0 to build statically-linked binaries deployable in scratch image

# Pre-compile tests to avoid I/O errors in ACI
RUN if [ "$build_test" = "True" ]; then CGO_ENABLED=0 go test -c && cd attest && CGO_ENABLED=0 go test -c && cd .. ; fi
RUN if [ "$build_test" = "False" ]; then rm -rf /usr/src/app/testdata; fi

RUN CGO_ENABLED=0 go build -v -o /usr/local/bin/app .

## Run
FROM mcr.microsoft.com/cbl-mariner/distroless/minimal:2.0

COPY --from=builder /usr/local/bin/app /usr/local/bin/app

# As *.test only exist when build_test=True, use .test* workaround so that copy does 
# not fail when these files do not exist
COPY --from=builder /usr/src/app/attestation-container.test* /usr/local/bin/attestation-container.test 
COPY --from=builder /usr/src/app/attest/attest.test* /usr/local/bin/attest.test 
COPY --from=builder /usr/src/app/attest/testdata/host_amd_certificate_env* /usr/local/bin/attest.test 

CMD ["app"]
