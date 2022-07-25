package helpers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
)

// RemoteImageFromImageName parses a given imageName reference and creates a v1.Image with
// provided remote.Option opts.
func RemoteImageFromImageName(imageName string, opts ...remote.Option) (v1.Image, error) {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return nil, err
	}

	return remote.Image(ref, opts...)
}

// ComputeLayerHashes computes cryptographic digests of image layers and returns
// them as slice of string hashes.
func ComputeLayerHashes(img v1.Image) ([]string, error) {
	imgLayers, err := img.Layers()
	if err != nil {
		return nil, err
	}

	var layerHashes []string

	for _, layer := range imgLayers {
		r, err := layer.Uncompressed()
		if err != nil {
			return nil, err
		}

		hashString, err := tar2ext4.ConvertAndComputeRootDigest(r)
		if err != nil {
			return nil, err
		}
		layerHashes = append(layerHashes, hashString)
	}
	return layerHashes, nil
}

// ParseEnvFromImage inspects the image spec and adds security policy rules for
// environment variables from the spec. Additionally, includes "TERM=xterm"
// rule, which is added for linux containers by CRI.
// func ParseEnvFromImage(img v1.Image) ([]string, error) {
// 	imgConfig, err := img.ConfigFile()
// 	if err != nil {
// 		return nil, err
// 	}

// 	// TODO: figure out what other env vars need to be in here
// 	// cri adds TERM=xterm for all workload containers. we add to all containers
// 	// to prevent any possible error
// 	envVars := append(imgConfig.Config.Env, "TERM=xterm")

// 	return envVars, nil
// }

// DefaultContainerConfigs returns a hardcoded slice of container configs, which should
// be included by default in the security policy.
// The slice includes only a sandbox pause container.
// TODO: take this out once we know the new version is what we want
// func DefaultContainerConfigs() []securitypolicy.ContainerConfig {
// 	pause := securitypolicy.ContainerConfig{
// 		ImageName: "k8s.gcr.io/pause:3.1",
// 		Command:   []string{"/pause"},
// 	}
// 	return []securitypolicy.ContainerConfig{pause}
// }
func DefaultContainerConfigs() ([]securitypolicy.ContainerConfig, error) {
	// TODO: un-hardcode this
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

	// container format in config file is same as policy.json so we need to convert them into a usable format
	outputContainerList, err := TranslateInputContainers(config.ExtraContainers)
	if err != nil {
		return nil, err
	}
	return outputContainerList, nil
}

// type for outermost config file
type HcsShimConfig struct {
	MinVersion string `json:"minVersion"`
	MaxVersion string `json:"maxVersion"`
}

type ConfigEnvVars struct {
	EnvVars []securitypolicy.InputEnvRuleConfig `json:"environmentVariables"`
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

// ParseWorkingDirFromImage inspects the image spec and returns working directory if
// one was set via CWD Docker directive, otherwise returns "/".
func ParseWorkingDirFromImage(img v1.Image) (string, error) {
	imgConfig, err := img.ConfigFile()
	if err != nil {
		return "", err
	}

	if imgConfig.Config.WorkingDir != "" {
		return imgConfig.Config.WorkingDir, nil
	}
	return "/", nil
}

// ParseCommandFromImage inspects the image and returns the command args, which
// is a combination of ENTRYPOINT and CMD Docker directives.
func ParseCommandFromImage(img v1.Image) ([]string, error) {
	imgConfig, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}

	cmdArgs := imgConfig.Config.Entrypoint
	cmdArgs = append(cmdArgs, imgConfig.Config.Cmd...)
	return cmdArgs, nil
}

func AddConfigEnvVars(containerConfigs []securitypolicy.InputContainerConfig) ([]securitypolicy.InputContainerConfig, error) {
	// TODO: un-hardcode this or make it static somewhere
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

	// TODO: could just append directly to list, would save a tiny amount of time
	// take all of the config env vars and put them into one array
	var configEnvVars []securitypolicy.InputEnvRuleConfig
	configEnvVars = append(configEnvVars, config.OpenGCS.EnvVars...)
	configEnvVars = append(configEnvVars, config.Fabric.EnvVars...)
	configEnvVars = append(configEnvVars, config.ManagedIdentity.EnvVars...)
	configEnvVars = append(configEnvVars, config.EnableRestart.EnvVars...)

	// add the env vars to every input container
	for i := range containerConfigs {
		containerConfigs[i].EnvRules = append(containerConfigs[i].EnvRules, configEnvVars...)
	}

	return containerConfigs, nil
}

// TranslateInputContainers standardizes the input format of the container policies to more closely show the
// output format. For example, environment variables in the input policy are represented by a Name, Value, and Strategy
// in the output they are a Strategy and Rule
// TODO: add error checking
func TranslateInputContainers(containerConfigs []securitypolicy.InputContainerConfig) ([]securitypolicy.ContainerConfig, error) {
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

	var policyContainers []securitypolicy.ContainerConfig
	for _, inputContainerConfig := range containerConfigs {
		// translate mounts
		var mounts []securitypolicy.MountConfig
		for _, mount := range inputContainerConfig.Mounts {
			r := securitypolicy.MountConfig{
				ContainerPath: mount.MountPath,
				// TODO HostPath: ,
				Readonly: mount.Readonly,
			}
			mounts = append(mounts, r)
		}

		// translate env vars
		var rules []securitypolicy.EnvRuleConfig
		for _, env := range inputContainerConfig.EnvRules {
			r := securitypolicy.EnvRuleConfig{
				Strategy: env.Strategy,
				Rule:     env.Name + "=" + env.Value,
			}
			rules = append(rules, r)
		}

		containerConfig := securitypolicy.ContainerConfig{
			ImageName: inputContainerConfig.ImageName,
			Command:   inputContainerConfig.Command,

			EnvRules:        rules,
			WorkingDir:      inputContainerConfig.WorkingDir,
			WaitMountPoints: inputContainerConfig.WaitMountPoints,
			Mounts:          mounts,
			AllowElevated:   inputContainerConfig.AllowElevated,
		}

		policyContainers = append(policyContainers, containerConfig)
	}
	return policyContainers, nil
}

// PolicyContainersFromConfigs returns a slice of securitypolicy.Container generated
// from a slice of securitypolicy.ContainerConfig's
func PolicyContainersFromConfigs(containerConfigs []securitypolicy.ContainerConfig) ([]*securitypolicy.Container, error) {
	var policyContainers []*securitypolicy.Container
	for _, containerConfig := range containerConfigs {
		var imageOptions []remote.Option

		if containerConfig.Auth.Username != "" && containerConfig.Auth.Password != "" {
			auth := authn.Basic{
				Username: containerConfig.Auth.Username,
				Password: containerConfig.Auth.Password}
			c, _ := auth.Authorization()
			authOption := remote.WithAuth(authn.FromConfig(*c))
			imageOptions = append(imageOptions, authOption)
		}

		img, err := RemoteImageFromImageName(containerConfig.ImageName, imageOptions...)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch image: %w", err)
		}

		layerHashes, err := ComputeLayerHashes(img)
		if err != nil {
			return nil, err
		}

		commandArgs := containerConfig.Command
		if len(commandArgs) == 0 {
			commandArgs, err = ParseCommandFromImage(img)
			if err != nil {
				return nil, err
			}
		}
		// add rules for all known environment variables from the configuration
		// these are in addition to "other rules" from the policy definition file
		// envVars, err := ParseEnvFromImage(img)
		// if err != nil {
		// 	return nil, err
		// }
		// envRules := securitypolicy.NewEnvVarRules(envVars)
		// envRules = append(envRules, containerConfig.EnvRules...)

		workingDir, err := ParseWorkingDirFromImage(img)
		if err != nil {
			return nil, err
		}

		if containerConfig.WorkingDir != "" {
			workingDir = containerConfig.WorkingDir
		}

		container, err := securitypolicy.CreateContainerPolicy(
			commandArgs,
			layerHashes,
			containerConfig.EnvRules,
			workingDir,
			containerConfig.WaitMountPoints,
			containerConfig.Mounts,
			containerConfig.AllowElevated,
		)
		if err != nil {
			return nil, err
		}
		policyContainers = append(policyContainers, container)
	}

	return policyContainers, nil
}
