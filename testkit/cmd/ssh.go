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
		ssh, err := env.SSHEndpoint()
		if err != nil {
			return err
		}
		fmt.Printf("%v\n", ssh)
		return nil
	},
}
