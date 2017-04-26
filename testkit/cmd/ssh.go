package cmd

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/docker/docker-e2e/testkit/machines"
)

var sshCmd = &cobra.Command{
	Use:   "ssh <machine> <cmds...>",
	Short: "Get the SSH invocation for an environment or machine",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("Environment or machine missing")
		}
		debug, err := cmd.Flags().GetBool("debug")
		if err != nil {
			return err
		}
		if debug {
			log.SetLevel(log.DebugLevel)
		}

		// TODO this isn't super efficient if you have many running environments
		// Consider adding an explicit "getter" for a discrete machine
		stacks, err := machines.ListEnvironments()
		if err != nil {
			return err
		}
		var m machines.Machine

		for _, stack := range stacks {
			// If the user specified the stack name, assume machine 0

			if stack.StackName == args[0] {
				m = stack.Machines[0]
				break
			} else {
				for _, machine := range stack.Machines {
					if machine.GetName() == args[0] {
						m = machine
					}
				}
			}
		}
		if m != nil {
			out, err := m.MachineSSH(strings.Join(args[1:], " "))
			fmt.Print(out)
			return err
		}
		return fmt.Errorf("unable to find matching stack or machine")

	},
}

func init() {
	sshCmd.Flags().BoolP("debug", "d", false, "enable verbose logging")
}
