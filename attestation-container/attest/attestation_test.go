package attest

import (
	"encoding/hex"
	"testing"
)

func assertEqual[T comparable](t *testing.T, description string, expect T, actual T) {
	if expect != actual {
		t.Fatalf("%s: Expected %v, but got %v", description, expect, actual)
	}
}

func TestFetchReport(t *testing.T) {
	// Report data for test
	reportData := [REPORT_DATA_SIZE]byte{}
	for i := 0; i < REPORT_DATA_SIZE; i++ {
		reportData[i] = byte(i)
	}

	reportBytes, err := FetchAttestationReportByte(reportData)
	if err != nil {
		t.Fatalf("Fetching report failed: %v", err)
	}
	expectedByteString := hex.EncodeToString(reportData[:])
	// Confirm `report data` (user provided 64 byte data) is correct
	// Offset of `report data` is specified in SEV-SNP Firmware ABI Specification Table 21
	// https://www.amd.com/en/support/tech-docs/sev-secure-nested-paging-firmware-abi-specification
	const REPORT_DATA_OFFSET = 80
	assertEqual(t, "Check report data", expectedByteString, hex.EncodeToString(reportBytes[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET+REPORT_DATA_SIZE]))
}
