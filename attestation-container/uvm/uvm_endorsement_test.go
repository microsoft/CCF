package uvm

import (
	"fmt"
	"testing"
)

func TestUVMEndorsement(t *testing.T) {
	envVarName := DEFAULT_UVM_ENDORSEMENT_ENV_VAR_NAME
	uvmEndorsement, err := FetchUVMEndorsement(envVarName)
	if err != nil {
		t.Fatalf("Couldn't get UVM endorsement: %s\nPlease make sure that %s environment variable is set before running test", err, envVarName)
	}
	if len(uvmEndorsement) == 0 {
		t.Fatalf("uvmEndorsement should not be empty")
	}
	fmt.Printf("UVM Endorsement: %s", uvmEndorsement)
}
