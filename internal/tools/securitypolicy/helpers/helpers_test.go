package helpers

import (
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestRemoteImageFromImageName(t *testing.T) {
	imageName := "mcr.microsoft.com/azure-cli:latest"
	var imageOptions []remote.Option
	img, err := RemoteImageFromImageName(imageName, imageOptions...)
	if err != nil {
		t.Errorf("unable to fetch image: %v", err)
	}

	size, err := img.Size()
	if size == 0 || err != nil {
		t.Errorf("image size is not 0")
	}
}

func TestParseWorkingDirFromImage(t *testing.T) {
	imageName := "mcr.microsoft.com/azure-cli:latest"
	var imageOptions []remote.Option
	img, err := RemoteImageFromImageName(imageName, imageOptions...)

	if err != nil {
		t.Errorf("unable to fetch image: %v", err)
	}

	workingDir, err := ParseWorkingDirFromImage(img)
	if err != nil {
		t.Errorf("unable to parse working dir: %v", err)
	}

	if workingDir != "/" {
		t.Errorf("working dir is not /")
	}
}

func TestParseCommandFromImage(t *testing.T) {
	imageName := "mcr.microsoft.com/azure-cli:latest"
	var imageOptions []remote.Option
	img, err := RemoteImageFromImageName(imageName, imageOptions...)
	if err != nil {
		t.Errorf("unable to fetch image: %v", err)
	}

	command, err := ParseCommandFromImage(img)
	if err != nil {
		t.Errorf("unable to parse command: %v", err)
	}

	expected := []string{"/bin/sh", "-c", "bash"}
	if !reflect.DeepEqual(command, expected) {
		t.Errorf("command is %s not %s", command, expected)
	}
}

func TestDefaultContainerConfigs(t *testing.T) {
	configs, err := DefaultContainerConfigs()
	if err != nil {
		t.Errorf("unable to get default container configs: %v", err)
	}
	if len(configs) != 1 {
		t.Errorf("expected 1 config, got %d", len(configs))
	}
}
