# Based on https://hub.docker.com/_/golang/

# To run this:
#   docker build -t attestation-container . [--build-arg build_test=True]
#   docker run -it --rm attestation-container

## Build
FROM golang:1.19 as builder
ARG build_test=False

WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Pre-compile tests to avoid I/O errors in ACI
RUN if [ "$build_test" = "True" ]; then CGO_ENABLED=0 go test -c && cd attest && CGO_ENABLED=0 go test -c && cd .. ; fi

RUN CGO_ENABLED=0 go build -v -o /usr/local/bin/app .

## Run
FROM ubuntu:latest

COPY --from=builder /usr/local/bin/app /app

# As *.test only exist when build_test=True, use .test* workaround
COPY --from=builder /usr/src/app/attestation-container.test* /usr/src/app/attestation-container.test 
COPY --from=builder /usr/src/app/attest/attest.test* /usr/src/app/attest/attest.test 

CMD ["tail", "-f", "/dev/null"]
