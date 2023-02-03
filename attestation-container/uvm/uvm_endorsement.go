package uvm

import (
	"fmt"
	"os"
)

const DEFAULT_UVM_ENDORSEMENT_ENV_VAR_NAME = "UVM_REFERENCE_INFO"

/*
Fetch UVM endorsement from environment variable as base64 encoded string.
*/
func FetchUVMEndorsement(envVarName string) (string, error) {
	uvmEndorsement, found := os.LookupEnv(envVarName)
	if !found {
		return "", fmt.Errorf("environment variable %s was not found", envVarName)
	}
	if len(uvmEndorsement) == 0 {
		return "", fmt.Errorf("value of %s is empty", envVarName)
	}
	return uvmEndorsement, nil
}
