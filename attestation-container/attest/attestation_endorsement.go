package attest

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"os"
	"time"
)

const (
	defaultBaseSec    = 2
	defaultMaxRetries = 5
)

const (
	AMD_ENDORSEMENT_HOST       = "https://kdsintf.amd.com"
	AZURE_ENDORSEMENT_HOST     = "https://global.acccache.azure.net"
	DEFAULT_ENDORSEMENT_ENVVAR = "UVM_HOST_AMD_CERTIFICATE" // SEV-SNP ACI deployments
)

type ACIEndorsements struct {
	CacheControl     string `json:"cacheControl"`
	VcekCert         string `json:"vcekCert"`
	CertificateChain string `json:"certificateChain"`
	Tcbm             string `json:"tcbm"`
}

func fetchWithRetry(requestURL string, baseSec int, maxRetries int) ([]byte, error) {
	if maxRetries < 0 {
		return nil, fmt.Errorf("invalid `maxRetries` value")
	}
	var err error
	retryCount := 0
	for retryCount <= maxRetries {
		if retryCount > 0 {
			// Exponential backoff
			maxDelay := math.Pow(float64(baseSec), float64(retryCount))
			delaySec := rand.Float64() * maxDelay
			delaySecInt := math.Min(math.MaxInt64, delaySec)
			time.Sleep(time.Duration(delaySecInt) * time.Second)
		}
		res, err := http.Get(requestURL)
		if err != nil {
			retryCount++
			continue
		}
		if 200 <= res.StatusCode && res.StatusCode < 300 {
			// Got successful status code 2xx
			defer res.Body.Close()
			resBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				retryCount++
				continue
			}
			return resBody, nil
		} else if res.StatusCode == 408 || res.StatusCode == 429 || 500 <= res.StatusCode {
			// Got status code that is worth to retry
			retryCount++
			continue
		} else {
			// Got status code that is not worth to retry
			defer res.Body.Close()
			resBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return nil, fmt.Errorf("got error while handling non successful response with status code %d: %s", res.StatusCode, err)
			}
			return nil, fmt.Errorf("GET request failed with status code %d: %s", res.StatusCode, resBody)
		}
	}
	return nil, err
}

func fetchAttestationEndorsementAzure(reportedTCBBytes [REPORTED_TCB_SIZE]byte, chipID string) ([]byte, error) {
	// Fetch attestation endorsement from Azure endpoint
	reportedTCB := binary.LittleEndian.Uint64(reportedTCBBytes[:])
	reportedTCBHex := fmt.Sprintf("%x", reportedTCB)
	requestURL := fmt.Sprintf("%s/SevSnpVM/certificates/%s/%s?api-version=2020-10-15-preview", AZURE_ENDORSEMENT_HOST, chipID, reportedTCBHex)
	return fetchWithRetry(requestURL, defaultBaseSec, defaultMaxRetries)
}

func fetchAttestationEndorsementAMD(reportedTCBBytes [REPORTED_TCB_SIZE]byte, chipID string) ([]byte, error) {
	// Fetch attestation endorsement from AMD endpoint
	// https://www.amd.com/en/support/tech-docs/versioned-chip-endorsement-key-vcek-certificate-and-kds-interface-specification

	boot_loader := reportedTCBBytes[0]
	tee := reportedTCBBytes[1]
	snp := reportedTCBBytes[6]
	microcode := reportedTCBBytes[7]
	const PRODUCT_NAME = "Milan"
	requestURL := fmt.Sprintf("%s/vcek/v1/%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d", AMD_ENDORSEMENT_HOST, PRODUCT_NAME, chipID, boot_loader, tee, snp, microcode)
	vcekCertDER, err := fetchWithRetry(requestURL, defaultBaseSec, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	vcek, err := x509.ParseCertificate(vcekCertDER)
	if err != nil {
		return nil, fmt.Errorf("Could not decode VCEK: %s", err)
	}
	endorsement := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: vcek.Raw})

	requestURLChain := fmt.Sprintf("%s/vcek/v1/%s/cert_chain", AMD_ENDORSEMENT_HOST, PRODUCT_NAME)
	endorsementCertChain, err := fetchWithRetry(requestURLChain, defaultBaseSec, defaultMaxRetries)
	if err != nil {
		return nil, err
	}
	return append(endorsement, endorsementCertChain...), nil
}

/*
Fetch attestation endorsement (VCEK-certificate) of SEV-SNP VM
*/
func FetchAttestationEndorsement(server string, reportedTCBBytes []byte, chipIDBytes []byte) ([]byte, error) {
	if server != "AMD" && server != "Azure" {
		return nil, fmt.Errorf("invalid endorsement server: %s", server)
	}
	if len(reportedTCBBytes) != REPORTED_TCB_SIZE {
		return nil, fmt.Errorf("Length of reportedTCBBytes should be %d", REPORTED_TCB_SIZE)
	}
	if len(chipIDBytes) != CHIP_ID_SIZE {
		return nil, fmt.Errorf("Length of chipIDBytes should be %d", CHIP_ID_SIZE)
	}

	reportedTCB := [REPORTED_TCB_SIZE]byte{}
	copy(reportedTCB[:], reportedTCBBytes)
	chipID := hex.EncodeToString(chipIDBytes)
	if server == "Azure" {
		return fetchAttestationEndorsementAzure(reportedTCB, chipID)
	} else {
		return fetchAttestationEndorsementAMD(reportedTCB, chipID)
	}
}

func ParseEndorsementACI(endorsementACIBase64 string) (ACIEndorsements, error) {
	endorsementsRaw, err := base64.StdEncoding.DecodeString(endorsementACIBase64)
	if err != nil {
		return ACIEndorsements{}, fmt.Errorf("Failed to decode ACI endorsements: %s", err)
	}

	endorsements := ACIEndorsements{}
	err = json.Unmarshal([]byte(endorsementsRaw), &endorsements)
	if err != nil {
		return ACIEndorsements{}, fmt.Errorf("Failed to unmarshal JSON ACI endorsements: %s", err)
	}
	return endorsements, nil
}

func ParseEndorsementACIFromEnvironment(endorsementEnvironmentVariable string) (ACIEndorsements, error) {
	endorsementEnvironment, ok := os.LookupEnv(endorsementEnvironmentVariable)
	if !ok {
		return ACIEndorsements{}, fmt.Errorf("Endorsement environment variable %s is not specified (or specify endorsement server)", endorsementEnvironmentVariable)
	}

	endorsement, err := ParseEndorsementACI(endorsementEnvironment)
	if err != nil {
		return ACIEndorsements{}, err
	}
	return endorsement, nil
}
