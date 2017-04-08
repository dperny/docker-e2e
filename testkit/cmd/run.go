package cmd

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker-e2e/testkit/environment"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run <cfg>",
	Short: "NOT YET PORTED - Provision a test environment and run tests",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("Config missing")
		}

		config, err := loadConfig(args[0])
		if err != nil {
			return err
		}

		var (
			env *environment.Environment
		)
		// TODO(dperny): ugly hack, cleanup
		t := time.Now()
		if cmd.Flags().Changed("name") {
			// TODO(dperny): error on this is unlikely, but handle anyway
			name, _ := cmd.Flags().GetString("name")
			// TODO(dperny): maximum length of name is...? 22? not sure
			if len(name) > 22 {
				return errors.New("Maximum length of name is 22 chars")
			}
			env, err = environment.Provision(newSession(), name, config.Environment)
			if err != nil {
				return err
			}
		} else {
			for r := 0; r < 100; r++ {
				name := fmt.Sprintf("docker-e2e-%d%02d%02d-%d", t.Year(), t.Month(), t.Day(), r)
				env, err = environment.Provision(newSession(), name, config.Environment)
				if err != nil {
					// Try with another name.
					if strings.Contains(err.Error(), "AlreadyExistsException") {
						continue
					}
					return err
				}
				break
			}
		}

		// Bring down the environment once we're done.
		// TODO(aluzzardi): This should be configurable (e.g. destroy "always", "on-success", "never", ...)
		defer env.Destroy()

		return runCommands(env, config)
	},
}

func init() {
	runCmd.Flags().String("name", "", "custom name for the stack")
}
