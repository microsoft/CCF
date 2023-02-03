package uvm

import (
	"fmt"
	"os"
	"testing"
)

func TestUVMEndorsement(t *testing.T) {
	// Prepare for test
	envVarName := DEFAULT_UVM_ENDORSEMENT_ENV_VAR_NAME
	const testEnvVarValue = "test base64 string"
	os.Setenv(envVarName, testEnvVarValue)

	// Test
	uvmEndorsement, err := FetchUVMEndorsement(envVarName)
	if err != nil {
		t.Fatalf("Couldn't get UVM endorsement: %s", err)
	}
	if uvmEndorsement != testEnvVarValue {
		t.Fatalf("Value doesn't match: '%s' was expected but got '%s'", testEnvVarValue, uvmEndorsement)
	}
	fmt.Printf("UVM Endorsement: %s", uvmEndorsement)
}
