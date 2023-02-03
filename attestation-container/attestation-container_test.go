package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"testing"
	"time"

	pb "microsoft/attestation-container/protobuf"

	"google.golang.org/grpc"
)

var (
	addr = flag.String("addr", "/tmp/attestation-container.sock", "the Unix domain socket address to connect to")
)

const TIMEOUT_IN_SEC = 10

func TestFetchReport(t *testing.T) {
	flag.Parse()
	// Set up a connection to the server.
	dialer := func(addr string, t time.Duration) (net.Conn, error) {
		return net.Dial("unix", addr)
	}
	conn, err := grpc.Dial(*addr, grpc.WithInsecure(), grpc.WithDialer(dialer))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewAttestationContainerClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT_IN_SEC*time.Second)
	defer cancel()
	// public key bytes in UTF-8 (https://go.dev/blog/strings)
	publicKey := []byte("public-key-contents")
	r, err := c.FetchAttestation(ctx, &pb.FetchAttestationRequest{ReportData: publicKey})
	if err != nil {
		log.Fatalf("could not get attestation: %v", err)
	}

	// Check each property's size is not zero
	// Note that validating properties is not Attestation Container's responsibility
	if len(r.GetAttestation()) == 0 {
		log.Fatalf("attestation is empty")
	}
	if len(r.GetAttestationEndorsementCertificates()) == 0 {
		log.Fatalf("attestation endorsement certificates are empty")
	}
	if len(r.GetUvmEndorsement()) == 0 {
		log.Fatalf("UVM endorsement is empty")
	}

	log.Printf("Attestation: %v", hex.EncodeToString(r.GetAttestation()))
	log.Printf("Attestation endorsement certificates: %v", hex.EncodeToString(r.GetAttestationEndorsementCertificates()))
	log.Printf("UVM endorsement: %s", r.GetUvmEndorsement())
}

func TestInputError(t *testing.T) {
	flag.Parse()
	// Set up a connection to the server.
	dialer := func(addr string, t time.Duration) (net.Conn, error) {
		return net.Dial("unix", addr)
	}
	conn, err := grpc.Dial(*addr, grpc.WithInsecure(), grpc.WithDialer(dialer))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewAttestationContainerClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT_IN_SEC*time.Second)
	defer cancel()
	publicKey := []byte("too long (longer than 64 bytes in utf-8) ------------------------")
	if _, err := c.FetchAttestation(ctx, &pb.FetchAttestationRequest{ReportData: publicKey}); err == nil {
		log.Fatalf("server should return input error for too large input")
	}
}
