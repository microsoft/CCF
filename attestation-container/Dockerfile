# Based on https://hub.docker.com/_/golang/

# To run this:
#   docker build -t attestation-container .
#   docker run -it --rm attestation-container

FROM golang:1.19
ARG build_test=False

WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Pre-compile tests to avoid I/O errors in ACI
RUN if [ "$build_test" = "True" ] ; then go test -c && cd attest && go test -c && cd .. ; fi

RUN go build -v -o /usr/local/bin/app .

CMD ["app"]
