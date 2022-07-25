package config

import (
	"encoding/json"
	"io/ioutil"

	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
)

// type for outermost config file
type HcsShimConfig struct {
	MinVersion string `json:"minVersion"`
	MaxVersion string `json:"maxVersion"`
}

type ConfigEnvVars struct {
	EnvVars []securitypolicy.InputEnvRuleConfig `json:"environmentVariables"`
}

type ConfigMount struct {
	SourceTable                     []MountSource                     `json:"source_table"`
	DefaultPolicy                   DefaultPolicy                     `json:"default_policy"`
	DefaultMountsUser               []DefaultMountsUser               `json:"default_mounts_user"`
	DefaultMountsGlobalInjectPolicy []DefaultMountsGlobalInjectPolicy `json:"default_mounts_global_inject_policy"`
	Containerd                      Containerd                        `json:"containerd"`
}

type MountSource struct {
	MountType string `json:"mountType"`
	Source    string `json:"source"`
}

type DefaultPolicy struct {
	Type    string                 `json:"type"`
	Options map[string]interface{} `json:"options"`
}

type DefaultMountsUser struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type DefaultMountsGlobalInjectPolicy struct {
	Destination string                 `json:"destination"`
	Options     map[string]interface{} `json:"options"`
	Source      string                 `json:"source"`
	Type        string                 `json:"type"`
}

type Containerd struct {
	DefaultWorkingDir string `json:"defaultWorkingDir"`
}

// type for the config file that's used as input for which version of hcsshim is needed,
// which default containers are put into the group, etc.
type ConfigFile struct {
	Version         string                                `json:"version"`
	ExtraContainers []securitypolicy.InputContainerConfig `json:"extra_containers"`
	HcsShimConfig   HcsShimConfig                         `json:"hcsshim_config"`
	OpenGCS         ConfigEnvVars                         `json:"openGCS"`
	Fabric          ConfigEnvVars                         `json:"fabric"`
	ManagedIdentity ConfigEnvVars                         `json:"managedIdentity"`
	EnableRestart   ConfigEnvVars                         `json:"enableRestart"`
	Mount           ConfigMount                           `json:"mount"`
}

func GetConfig() (*ConfigFile, error) {
	configFile := "./internal_config.json"
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	config := &ConfigFile{}
	err = json.Unmarshal(configData, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
