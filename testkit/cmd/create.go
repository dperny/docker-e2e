package cmd

import (
	"errors"
	"fmt"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/docker/docker-e2e/testkit/machines"
)

var createCmd = &cobra.Command{
	Use:   "create <linux_count> <windows_count>",
	Short: "Provision a test environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		debug, err := cmd.Flags().GetBool("debug")
		if err != nil {
			return err
		}
		if debug {
			log.SetLevel(log.DebugLevel)
		}
		if len(args) == 0 {
			return errors.New("Config missing")
		}

		linuxCount, err := strconv.Atoi(args[0])
		if err != nil {
			log.Fatal(err)
		}
		windowsCount, err := strconv.Atoi(args[1])
		if err != nil {
			log.Fatal(err)
		}

		lm, wm, err := machines.GetTestMachines(linuxCount, windowsCount)
		if err != nil {
			log.Fatalf("Failure: %s", err)
		}
		for _, m := range append(lm, wm...) {
			fmt.Println(m.GetConnectionEnv())
			fmt.Println("")
		}
		return nil
	},
}

func init() {
	createCmd.Flags().BoolP("debug", "d", false, "enable verbose logging")
}
