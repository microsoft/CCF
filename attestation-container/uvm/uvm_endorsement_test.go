package uvm

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"testing"
)

func TestUVMEndorsement(t *testing.T) {
	// Prepare for test
	securityContextDirectory, err := ioutil.TempDir("", "security-context")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(securityContextDirectory)

	log.Print(securityContextDirectory)

	const testString = "test"
	testStringBase64 := base64.StdEncoding.EncodeToString([]byte(testString))

	// Valid
	content := []byte(testStringBase64)
	err = ioutil.WriteFile(path.Join(securityContextDirectory, UVM_ENDORSEMENTS_FILE_NAME), content, 0666)
	if err != nil {
		log.Fatal(err)
	}
	uvmEndorsement, err := ParseUVMEndorsement(securityContextDirectory)
	if err != nil {
		t.Fatalf("Couldn't get UVM endorsement: %s", err)
	}
	if string(uvmEndorsement) != testString {
		t.Fatalf("Value doesn't match: '%s' was expected but got '%s'", testString, uvmEndorsement)
	}

	// Invalid Based 64
	content = content[1:]
	err = ioutil.WriteFile(path.Join(securityContextDirectory, UVM_ENDORSEMENTS_FILE_NAME), content, 0666)
	if err != nil {
		log.Fatal(err)
	}
	uvmEndorsement, err = ParseUVMEndorsement(securityContextDirectory)
	if !strings.Contains(err.Error(), "Failed to decode base64 string: illegal base64 data") {
		t.Fatalf("Couldn't get UVM endorsement: %s", err)
	}
}
