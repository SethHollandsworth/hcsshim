package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	importConfig "github.com/Microsoft/hcsshim/internal/tools/securitypolicy/config"
	"github.com/Microsoft/hcsshim/internal/tools/securitypolicy/helpers"
	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
)

var (
	configFile = flag.String("c", "", "config")
	outputJSON = flag.Bool("j", false, "json")
)

func main() {
	flag.Parse()
	if flag.NArg() != 0 || len(*configFile) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	err := func() (err error) {
		configData, err := ioutil.ReadFile(*configFile)
		if err != nil {
			return err
		}

		config := &importConfig.InputPolicyConfig{}

		// decide whether we're parsing toml or json
		if strings.HasSuffix(*configFile, ".toml") {
			err = toml.Unmarshal(configData, config)
			if err != nil {
				return err
			}
		} else {
			err = json.Unmarshal(configData, config)
			if err != nil {
				return err
			}
		}

		// TODO: do a lot of error checking on the input json to make sure it has all the necessary pieces.
		// make it so it reports all the issues at one time instead of stopping after it finds one issue

		policy, err := func() (*securitypolicy.SecurityPolicy, error) {
			if config.AllowAll {
				return securitypolicy.NewOpenDoorPolicy(), nil
			} else {
				return createPolicyFromConfig(config)
			}
		}()

		if err != nil {
			return err
		}

		j, err := json.Marshal(policy)
		if err != nil {
			return err
		}

		if *outputJSON {
			fmt.Printf("%s\n", j)
		}

		b := base64.StdEncoding.EncodeToString(j)
		fmt.Printf("%s\n", b)

		return nil
	}()

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func createPolicyFromConfig(config *importConfig.InputPolicyConfig) (*securitypolicy.SecurityPolicy, error) {

	// add all the env vars from configuration file
	addedEnvVars, err := helpers.AddConfigEnvVars(config.Containers)
	if err != nil {
		return nil, err
	}

	// need to translate the input from policy.json format to the expected json that gets base64 encoded
	translatedInput, err := helpers.TranslateInputContainers(addedEnvVars)
	if err != nil {
		return nil, err
	}

	// Add default containers to the policy config to get the root hash
	// and any environment variable rules we might need
	defaultContainers, err := helpers.DefaultContainerConfigs()
	if err != nil {
		return nil, err
	}

	outConfig := securitypolicy.PolicyConfig{
		Containers: append(translatedInput, defaultContainers...),
		AllowAll:   config.AllowAll,
	}

	//
	policyContainers, err := helpers.PolicyContainersFromConfigs(outConfig.Containers)
	if err != nil {
		return nil, err
	}

	return securitypolicy.NewSecurityPolicy(false, policyContainers), nil
}
