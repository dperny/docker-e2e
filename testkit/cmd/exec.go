package cmd

import (
	"errors"

	"github.com/docker/docker-e2e/testkit/environment"
	"github.com/spf13/cobra"
)

func runCommands(c *environment.Environment, cfg *Config) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Disconnect()

	for _, cmd := range cfg.Commands {
		if err := c.Run(cmd); err != nil {
			return err
		}
	}

	return nil
}

var execCmd = &cobra.Command{
	Use:   "exec <config> <environment>",
	Short: "NOT YET PORTED - Execute tests in an already provisioned environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return errors.New("Config or AWS Stack ID missing")
		}

		config, err := loadConfig(args[0])
		if err != nil {
			return err
		}

		env := environment.New(args[1], newSession())
		return runCommands(env, config)
	},
}
