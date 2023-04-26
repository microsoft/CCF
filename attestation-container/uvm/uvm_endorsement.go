package uvm

import (
	"encoding/base64"
	"fmt"
	"os"
	"path"
)

const (
	UVM_ENDORSEMENTS_FILE_NAME = "reference-info-base64"
)

/*
Gets UVM endorsement from environment variable as base64 encoded string and returns as []byte.
*/
func ParseUVMEndorsement(securityContextDirectory string) ([]byte, error) {
	uvmEndorsementsBase64, err := os.ReadFile(path.Join(securityContextDirectory, UVM_ENDORSEMENTS_FILE_NAME))
	if err != nil {
		return nil, err
	}

	uvmEndorsement, err := base64.StdEncoding.DecodeString(string(uvmEndorsementsBase64))
	if err != nil {
		return nil, fmt.Errorf("Failed to decode base64 string: %s", err)
	}

	return uvmEndorsement, nil
}
