package cmd

import (
	"errors"
	"fmt"

	"github.com/docker/docker-e2e/testkit/machines"
	"github.com/spf13/cobra"
)

// TODO(dperny) accept a list of environments to delete
var removeCmd = &cobra.Command{
	Use:   "rm <environmentname>",
	Short: "delete an environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("Environment name missing")
		}
		if err := machines.DestroyEnvironment(args[0]); err != nil {
			return err
		}
		fmt.Printf("%v\n", args[0])
		return nil
	},
}
