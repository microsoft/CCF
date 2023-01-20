package attest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Data structures are based on SEV-SNP Firmware ABI Specification
// https://www.amd.com/en/support/tech-docs/sev-secure-nested-paging-firmware-abi-specification

const (
	ATTESTATION_REPORT_SIZE = 1184 // Size of ATTESTATION_REPORT (Table 21)
	REPORT_DATA_SIZE        = 64   // Size of REPORT_DATA_SIZE in ATTESTATION_REPORT
	REPORTED_TCB_OFFSET     = 384
	REPORTED_TCB_SIZE       = 8
	CHIP_ID_OFFSET          = 416
	CHIP_ID_SIZE            = 64
	REPORT_REQ_SIZE         = 96   // Size of MSG_REPORT_REQ (Table 20)
	REPORT_RSP_SIZE         = 1280 // Size of MSG_REPORT_RSP (Table 23)
	PAYLOAD_SIZE            = 40   // Size of sev_snp_guest_request struct from sev-snp driver include/uapi/linux/psp-sev-guest.h
)

// Message Type Encodings (Table 100)
const (
	MSG_REPORT_REQ = 5
	MSG_REPORT_RSP = 6
)

// From sev-snp driver include/uapi/linux/psp-sev-guest.h
const SEV_SNP_GUEST_MSG_REPORT = 3223868161

const SNP_DEVICE_PATH = "/dev/sev"

/*
Creates and returns MSG_REPORT_REQ message bytes (SEV-SNP Firmware ABI Specification Table 20)
*/
func createReportReqBytes(reportData [REPORT_DATA_SIZE]byte) [REPORT_REQ_SIZE]byte {
	reportReqBytes := [REPORT_REQ_SIZE]byte{}
	copy(reportReqBytes[0:REPORT_DATA_SIZE], reportData[:])
	return reportReqBytes
}

/*
Creates and returns byte array of the following C struct

// From sev-snp driver include/uapi/linux/psp-sev-guest.h
// struct sev_snp_guest_request {
//   uint8_t req_msg_type;
//   uint8_t rsp_msg_type;
//   uint8_t msg_version;
//   uint16_t request_len;
//   uint64_t request_uaddr;
//   uint16_t response_len;
//   uint64_t response_uaddr;
//   uint32_t error;		// firmware error code on failure (see psp-sev.h)
// };

The padding is based on Section 3.1.2 of System V ABI for AMD64
https://www.uclibc.org/docs/psABI-x86_64.pdf
*/
func createPayloadBytes(reportReqPtr uintptr, ReportRespPtr uintptr) ([PAYLOAD_SIZE]byte, error) {
	payload := [PAYLOAD_SIZE]byte{}
	var buf bytes.Buffer
	// req_msg_type
	if err := binary.Write(&buf, binary.LittleEndian, uint8(MSG_REPORT_REQ)); err != nil {
		return payload, err
	}
	// rsp_msg_type
	if err := binary.Write(&buf, binary.LittleEndian, uint8(MSG_REPORT_RSP)); err != nil {
		return payload, err
	}
	// msg_version
	if err := binary.Write(&buf, binary.LittleEndian, uint8(1)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint8(0)); err != nil {
		return payload, err
	}
	// request_len
	if err := binary.Write(&buf, binary.LittleEndian, uint16(REPORT_REQ_SIZE)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint16(0)); err != nil {
		return payload, err
	}
	// request_uaddr
	if err := binary.Write(&buf, binary.LittleEndian, uint64(reportReqPtr)); err != nil {
		return payload, err
	}
	// response_len
	if err := binary.Write(&buf, binary.LittleEndian, uint16(REPORT_RSP_SIZE)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, [3]uint16{}); err != nil {
		return payload, err
	}
	// response_uaddr
	if err := binary.Write(&buf, binary.LittleEndian, uint64(ReportRespPtr)); err != nil {
		return payload, err
	}
	// error
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
		return payload, err
	}
	for i, x := range buf.Bytes() {
		payload[i] = x
	}
	return payload, nil
}

func FetchAttestationReportByte(reportData [64]byte) ([]byte, error) {
	fd, err := unix.Open(SNP_DEVICE_PATH, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	reportReqBytes := createReportReqBytes(reportData)
	// MSG_REPORT_RSP message bytes (SEV-SNP Firmware Firmware ABI Specification Table 23)
	reportRspBytes := [REPORT_RSP_SIZE]byte{}
	payload, err := createPayloadBytes(uintptr(unsafe.Pointer(&reportReqBytes[0])), uintptr(unsafe.Pointer(&reportRspBytes[0])))
	if err != nil {
		return nil, err
	}

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(SEV_SNP_GUEST_MSG_REPORT),
		uintptr(unsafe.Pointer(&payload[0])),
	)

	if errno != 0 {
		return nil, fmt.Errorf("ioctl failed:%v", errno)
	}

	if status := binary.LittleEndian.Uint32(reportRspBytes[0:4]); status != 0 {
		return nil, fmt.Errorf("fetching attestation report failed. status: %v", status)
	}
	const SNP_REPORT_OFFSET = 32
	return reportRspBytes[SNP_REPORT_OFFSET : SNP_REPORT_OFFSET+ATTESTATION_REPORT_SIZE], nil
}
