package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"

	"microsoft/attestation-container/attest"
	pb "microsoft/attestation-container/protobuf"
	"microsoft/attestation-container/uvm"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	socketAddress                = flag.String("socket-address", "/tmp/attestation-container.sock", "The socket address of Unix domain socket (UDS)")
	attestationEndorsementEnvVar = flag.String("attestation-endorsement-envvar", attest.DEFAULT_ENDORSEMENT_ENVVAR, "Name of environment variable containing report endorsements as base64-encoded JSON object")
	attestationEndorsementServer = flag.String("attestation-endorsement-server", "", "Server to fetch attestation endorsement. If set, attestation-endorsement-envvar is ignored. Value is either 'Azure' or 'AMD'")
	uvmEndorsementEnvVar         = flag.String("uvm-endorsement-envvar", uvm.DEFAULT_UVM_ENDORSEMENT_ENV_VAR_NAME, "Name of UVM endorsement environment variable")

	attestationEndorsementEnvVarValue *attest.ACIEndorsements = nil
	uvmEndorsementEnvVarValue         *[]byte                 = nil
)

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

	var attestationEndorsement []byte
	if attestationEndorsementEnvVarValue == nil {
		reportedTCBBytes := reportBytes[attest.REPORTED_TCB_OFFSET : attest.REPORTED_TCB_OFFSET+attest.REPORTED_TCB_SIZE]
		chipIDBytes := reportBytes[attest.CHIP_ID_OFFSET : attest.CHIP_ID_OFFSET+attest.CHIP_ID_SIZE]
		attestationEndorsement, err = attest.FetchAttestationEndorsement(*attestationEndorsementServer, reportedTCBBytes, chipIDBytes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to fetch attestation endorsement: %s", err)
		}
	} else {
		attestationEndorsement = append(attestationEndorsement, attestationEndorsementEnvVarValue.VcekCert...)
		attestationEndorsement = append(attestationEndorsement, attestationEndorsementEnvVarValue.CertificateChain...)
	}

	return &pb.FetchAttestationReply{Attestation: reportBytes, AttestationEndorsementCertificates: attestationEndorsement, UvmEndorsement: *uvmEndorsementEnvVarValue}, nil
}

func validateFlags() {
	if *attestationEndorsementServer != "" && *attestationEndorsementServer != "AMD" && *attestationEndorsementServer != "Azure" {
		log.Fatalf("invalid --attestation-endorsement-server value %s (valid values: 'AMD', 'Azure')", *attestationEndorsementServer)
	}
}

func main() {
	log.Println("Attestation container started.")

	if _, err := os.Stat(attest.SNP_DEVICE_PATH); err == nil {
		log.Printf("%s is detected\n", attest.SNP_DEVICE_PATH)
	} else if errors.Is(err, os.ErrNotExist) {
		log.Fatalf("%s is not detected", attest.SNP_DEVICE_PATH)
	} else {
		log.Fatalf("Unknown error: %s", err)
	}

	flag.Parse()
	validateFlags()

	if *attestationEndorsementServer == "" {
		log.Printf("Reading report endorsement from environment variable %s", *attestationEndorsementEnvVar)
		attestationEndorsementEnvVarValue = new(attest.ACIEndorsements)
		var err error
		*attestationEndorsementEnvVarValue, err = attest.ParseEndorsementACIFromEnvironment(*attestationEndorsementEnvVar)
		if err != nil {
			log.Fatalf(err.Error())
		}
	} else {
		log.Printf("Retrieving report endorsement from server %s", *attestationEndorsementServer)
	}

	var err error
	*uvmEndorsementEnvVarValue, err = uvm.ParseUVMEndorsement(*uvmEndorsementEnvVar)
	if err != nil {
		log.Fatalf(err.Error())
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
