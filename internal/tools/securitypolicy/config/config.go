package importConfig

import (
	"encoding/json"
	"io/ioutil"
	"runtime"
	"strings"
)

// type for outermost config file
type HcsShimConfig struct {
	MinVersion string `json:"minVersion"`
	MaxVersion string `json:"maxVersion"`
}

// EnvRuleConfig contains toml or JSON config for environment variable
// security policy enforcement.
type InputEnvRuleConfig struct {
	Strategy EnvVarRule `json:"strategy" toml:"strategy"`
	Name     string     `json:"name" toml:"name"`
	Value    string     `json:"value" toml:"value"`
}

type ConfigEnvVars struct {
	EnvVars []InputEnvRuleConfig `json:"environmentVariables"`
}
type StringArrayMap struct {
	Elements map[string]string `json:"elements"`
	Length   int               `json:"length"`
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
	Type    string         `json:"type"`
	Options StringArrayMap `json:"options"`
}

type DefaultMountsUser struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type DefaultMountsGlobalInjectPolicy struct {
	Destination string         `json:"destination"`
	Options     StringArrayMap `json:"options"`
	Source      string         `json:"source"`
	Type        string         `json:"type"`
}

type Containerd struct {
	DefaultWorkingDir string `json:"defaultWorkingDir"`
}

// type for the config file that's used as input for which version of hcsshim is needed,
// which default containers are put into the group, etc.
type ConfigFile struct {
	Version         string                 `json:"version"`
	ExtraContainers []InputContainerConfig `json:"extra_containers"`
	HcsShimConfig   HcsShimConfig          `json:"hcsshim_config"`
	OpenGCS         ConfigEnvVars          `json:"openGCS"`
	Fabric          ConfigEnvVars          `json:"fabric"`
	ManagedIdentity ConfigEnvVars          `json:"managedIdentity"`
	EnableRestart   ConfigEnvVars          `json:"enableRestart"`
	Mount           ConfigMount            `json:"mount"`
}

// ContainerConfig contains toml or JSON config for container described
// in security policy.
type InputContainerConfig struct {
	ImageName       string               `json:"containerImage" toml:"containerImage"`
	Command         []string             `json:"command" toml:"command"`
	EnvRules        []InputEnvRuleConfig `json:"environmentVariables" toml:"environmentVariables"`
	WorkingDir      string               `json:"workingDir" toml:"workingDir"`
	WaitMountPoints []string             `json:"wait_mount_points" toml:"wait_mount_points"`
	Mounts          []InputMountConfig   `json:"mounts" toml:"mount"`
	Auth            InputAuthConfig      `json:"auth" toml:"auth"`
	AllowElevated   bool                 `json:"allow_elevated" toml:"allow_elevated"`
}

// InputAuthConfig contains config for container authentication
type InputAuthConfig struct {
	Username string `json:"username" toml:"username"`
	Password string `json:"password" toml:"password"`
	Token    string `json:"token" toml:"token"`
}

// MountConfig contains toml or JSON config for mount security policy
// constraint description.
type InputMountConfig struct {
	MountType string `json:"mountType" toml:"mountType"`
	MountPath string `json:"mountPath" toml:"mountPath"`
	Readonly  bool   `json:"readonly" toml:"readonly"`
}

// PolicyConfig contains toml or JSON config for security policy.
type InputPolicyConfig struct {
	AllowAll   bool                   `json:"allow_all" toml:"allow_all"`
	Containers []InputContainerConfig `json:"containers" toml:"container"`
}

type EnvVarRule string

// GetConfig grabs the initial config from the config file and returns it as an object
func GetConfig() (*ConfigFile, error) {
	_, filename, _, _ := runtime.Caller(0)
	// extract the absolute path of the config file
	configFilePath := filename[:strings.LastIndex(filename, "/")] + "/config.json"
	configData, err := ioutil.ReadFile(configFilePath)
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
