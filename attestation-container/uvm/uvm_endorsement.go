package uvm

import (
	"encoding/base64"
	"fmt"
	"os"
)

const DEFAULT_UVM_ENDORSEMENT_ENV_VAR_NAME = "UVM_REFERENCE_INFO"

/*
Gets UVM endorsement from environment variable as base64 encoded string and returns as []byts.
*/
func ParseUVMEndorsement(envVarName string) ([]byte, error) {
	uvmEndorsementBase64, found := os.LookupEnv(envVarName)
	if !found {
		return nil, fmt.Errorf("environment variable %s was not found", envVarName)
	}
	if len(uvmEndorsementBase64) == 0 {
		return nil, fmt.Errorf("value of %s is empty", envVarName)
	}

	uvmEndorsement, err := base64.StdEncoding.DecodeString(uvmEndorsementBase64)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode base64 string: %s", err)
	}

	return uvmEndorsement, nil
}
