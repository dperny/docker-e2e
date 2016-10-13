package cmd

import (
	"fmt"

	"github.com/docker/docker-e2e/testkit/environment"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "ls",
	Short: "list all environments",
	RunE: func(cmd *cobra.Command, args []string) error {
		stacks, err := environment.List(newSession())
		if err != nil {
			return err
		}

		for _, stack := range stacks {
			if cmd.Flags().Changed("full") {
				fmt.Printf("%v\n", *stack)
			} else {
				fmt.Printf("%v\n", *stack.StackName)
			}
		}
		return nil
	},
}

func init() {
	// TODO(dperny) consider shorthand `-f`? or perhaps print this by default and pass a flag for just names?
	listCmd.Flags().Bool("full", false, "Display full environment structure instead of just names")
}
