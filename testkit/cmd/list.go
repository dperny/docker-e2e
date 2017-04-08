package cmd

import (
	"fmt"

	"github.com/docker/docker-e2e/testkit/machines"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "ls",
	Short: "list all environments",
	RunE: func(cmd *cobra.Command, args []string) error {
		stacks, err := machines.ListEnvironments()
		if err != nil {
			return err
		}

		for _, stack := range stacks {
			if cmd.Flags().Changed("full") {
				fmt.Printf("%s\n", stack.StackName)
				for _, m := range stack.Machines {
					ip, err := m.GetIP()
					if err != nil {
						ip = err.Error()
					}
					fmt.Printf("\t%s %s\n", m.GetName(), ip)
				}
			} else {
				fmt.Printf("%v\n", stack.StackName)
			}
		}
		return nil
	},
}

func init() {
	// TODO(dperny) consider shorthand `-f`? or perhaps print this by default and pass a flag for just names?
	listCmd.Flags().Bool("full", false, "Display full environment structure instead of just names")
}
