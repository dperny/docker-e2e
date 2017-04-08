package cmd

import (
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/docker/docker-e2e/testkit/environment"
	"github.com/spf13/cobra"
)

const (
	// TODO(dperny): make configurable; probably a flag
	region = "us-east-1"
)

type Config struct {
	Environment *environment.Config `yaml:"environment,omitempty"`

	Commands []string `yaml:"commands,omitempty"`
}

func loadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return config, nil
}

func newSession() *session.Session {
	s, err := session.NewSession(aws.NewConfig().WithRegion(region))
	if err != nil {
		panic(err)
	}
	return s
}

var mainCmd = &cobra.Command{
	Use:   os.Args[0],
	Short: "Docker End to End Testing",
}

func init() {
	mainCmd.AddCommand(
		envCmd,
		createCmd,
		execCmd,
		runCmd,
		sshCmd,
		listCmd,
		removeCmd,
	)
}

func Execute() error {
	return mainCmd.Execute()
}
