package uvm

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestUVMEndorsement(t *testing.T) {
	// Prepare for test
	envVarName := DEFAULT_UVM_ENDORSEMENT_ENV_VAR_NAME
	const testString = "test"
	testEnvVarValue := base64.StdEncoding.EncodeToString([]byte(testString))

	// Valid
	os.Setenv(envVarName, testEnvVarValue)
	uvmEndorsement, err := ParseUVMEndorsement(envVarName)
	if err != nil {
		t.Fatalf("Couldn't get UVM endorsement: %s", err)
	}
	if string(uvmEndorsement) != testString {
		t.Fatalf("Value doesn't match: '%s' was expected but got '%s'", testEnvVarValue, uvmEndorsement)
	}

	// Invalid Based 64
	brokenBase64 := testEnvVarValue[1:]
	os.Setenv(envVarName, brokenBase64)
	uvmEndorsement, err = ParseUVMEndorsement(envVarName)
	if !strings.Contains(err.Error(), "Failed to decode base64 string: illegal base64 data") {
		t.Fatalf("Couldn't get UVM endorsement: %s", err)
	}
}
