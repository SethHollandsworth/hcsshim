package importConfig

import (
	"testing"
)

func TestGetConfig(t *testing.T) {

	actual, err := GetConfig()
	if err != nil {
		t.Errorf("GetConfig() failed with error: %v", err)
	}
	if actual == nil {
		t.Errorf("GetConfig() returned nil")
	}

	if !(len(actual.Mount.DefaultMountsGlobalInjectPolicy) == 2) {
		t.Errorf("GetConfig() returned incorrect number of global default mounts")
	}
}
