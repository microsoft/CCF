package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"encoding/base64"
	"encoding/json"

	"microsoft/attestation-container/attest"
	pb "microsoft/attestation-container/protobuf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultEndorsementEnvironmentVariable = "UVM_HOST_AMD_CERTIFICATE" // SEV-SNP ACI deployments
)

var (
	socketAddress     = flag.String("socket-address", "/tmp/attestation-container.sock", "The socket address of Unix domain socket (UDS)")
	endorsementEnvironmentVariable = flag.String("endorsement-envvar", defaultEndorsementEnvironmentVariable, "Name of environment variable containing report endorsements as base64-encoded JSON object")
	endorsementServer = flag.String("endorsement-server", "", "Server to fetch attestation endorsement. If set, endorsement-envvar is ignored. Value is either 'Azure' or 'AMD'")
)

type ACIEndorsements struct {
	CacheControl string `json:"cacheControl"`
    VcekCert string `json:"vcekCert"`
    CertificateChain string `json:"certificateChain"`
    Tcbm string `json:"tcbm"`
}

type server struct {
	pb.UnimplementedAttestationContainerServer
}

func (s *server) FetchAttestation(ctx context.Context, in *pb.FetchAttestationRequest) (*pb.FetchAttestationReply, error) {
	reportData := [attest.REPORT_DATA_SIZE]byte{}
	if len(in.GetReportData()) > attest.REPORT_DATA_SIZE {
		return nil, status.Errorf(codes.InvalidArgument, "`report_data` needs to be smaller than %d bytes. size: %d bytes", attest.REPORT_DATA_SIZE, len(in.GetReportData()))
	}
	copy(reportData[:], in.GetReportData())
	reportBytes, err := attest.FetchAttestationReportByte(reportData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch attestation report: %s", err)
	}

	var endorsement []byte
	if (*endorsementServer != "") {
		reportedTCBBytes := reportBytes[attest.REPORTED_TCB_OFFSET : attest.REPORTED_TCB_OFFSET+attest.REPORTED_TCB_SIZE]
		chipIDBytes := reportBytes[attest.CHIP_ID_OFFSET : attest.CHIP_ID_OFFSET+attest.CHIP_ID_SIZE]
		endorsement, err = attest.FetchAttestationEndorsement(*endorsementServer, reportedTCBBytes, chipIDBytes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to fetch attestation endorsement: %s", err)
		}
	} else {
		aciEndorsement := parseEndorsementFromEnvironment(*endorsementEnvironmentVariable)
		endorsement = append(endorsement, aciEndorsement.VcekCert...)
		endorsement = append(endorsement, aciEndorsement.CertificateChain...)
		log.Printf("%s", endorsement)
	}


	return &pb.FetchAttestationReply{Attestation: reportBytes, AttestationEndorsementCertificates: endorsement}, nil
}

func validateFlags() {
	if *endorsementServer != "" && *endorsementServer != "AMD" && *endorsementServer != "Azure" {
		log.Fatalf("invalid --endorsement-server value %s (valid values: 'AMD', 'Azure')", *endorsementServer)
	}
}

func parseEndorsementFromEnvironment(endorsementEnvironmentVariable string) ACIEndorsements {
	endorsementEnvironment, ok := os.LookupEnv(endorsementEnvironmentVariable)
	if !ok {
		log.Fatalf("Endorsement environment variable %s is not specified", endorsementEnvironmentVariable)
	}

	endorsementsRaw, err := base64.StdEncoding.DecodeString(endorsementEnvironment)
	if err != nil {
		log.Fatalf("Failed to decode base64 environment variable %s: %s", endorsementEnvironmentVariable, err)
	}

	endorsements := ACIEndorsements{}
	err = json.Unmarshal([]byte(endorsementsRaw), &endorsements)
	if err != nil {
		log.Fatalf("Failed to unmarshal JSON object: %s", err)
	}
	return endorsements
}

func main() {
	fmt.Println("Attestation container started.")

	if _, err := os.Stat(attest.SNP_DEVICE_PATH); err == nil {
		fmt.Printf("%s is detected\n", attest.SNP_DEVICE_PATH)
	} else if errors.Is(err, os.ErrNotExist) {
		log.Fatalf("%s is not detected", attest.SNP_DEVICE_PATH)
	} else {
		log.Fatalf("Unknown error: %s", err)
	}

	flag.Parse()
	validateFlags()

	// TODO: Parse this once and for all!
	if (*endorsementServer == "") {
		parseEndorsementFromEnvironment(*endorsementEnvironmentVariable)
	}

	// Cleanup
	if _, err := os.Stat(*socketAddress); err == nil {
		if err := os.RemoveAll(*socketAddress); err != nil {
			log.Fatalf("Failed to clean up socket: %s", err)
		}
	}

	// Create parent directory for socketAddress
	socketDir := filepath.Dir(*socketAddress)
	// os.MkdirAll doesn't return error when the directory already exists
	if err := os.MkdirAll(socketDir, os.ModePerm); err != nil {
		log.Fatalf("Failed to create directory for Unix domain socket: %s", err)
	}

	lis, err := net.Listen("unix", *socketAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterAttestationContainerServer(s, &server{})
	log.Printf("Server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
