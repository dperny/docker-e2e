package cmd

import (
	"errors"
	"fmt"

	"github.com/docker/docker-e2e/testkit/environment"
	"github.com/spf13/cobra"
)

var sshCmd = &cobra.Command{
	Use:   "ssh <env>",
	Short: "Get the SSH endpoint for an environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("Environment missing")
		}

		env := environment.New(args[0], newSession())
		if ssh, err := env.SSHEndpoint(); err != nil {
			return err
		} else {
			fmt.Printf("%v\n", ssh)
			return nil
		}
	},
}
