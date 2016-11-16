package cmd

import (
	"errors"
	"fmt"

	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/docker/docker-e2e/testkit/environment"
	"github.com/spf13/cobra"
)

var attachCmd = &cobra.Command{
	Use:   "attach <env>",
	Short: "attach a local socket to the docker socket on a remote host",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("Environment missing")
		}

		env := environment.New(args[0], newSession())
		host, err := env.SSHEndpoint()
		if err != nil {
			return err
		}

		var socket string
		if cmd.Flags().Changed("socket") {
			socket, err = cmd.Flags().GetString("socket")
			if err != nil {
				return err
			}
		} else {
			dir, err := os.Getwd()
			if err != nil {
				return err
			}
			socket = dir + "/docker.sock"
		}
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			return err
		}
		err = openTunnel(host, socket, verbose)
		return err
	},
}

// openTunnel opens a tunnel over ssh from a socket in the local directory to
// the docker socket on the cluster.
func openTunnel(host, socket string, verbose bool) error {
	fmt.Printf("opening tunnel to %v\n", host)
	// set identity file
	// TODO(dperny) this is copied out of loadSSHKeys. possible to DRY?
	usr, err := user.Current()
	if err != nil {
		return err
	}
	keyDir := filepath.Join(usr.HomeDir, "/.ssh/")
	keys, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return err
	}

	keyfiles := []string{}
	for _, f := range keys {
		keyPath := filepath.Join(keyDir, f.Name())
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			continue
		}
		// we do ParsePrivateKey to see if the key is in fact a key. if it's
		// not, this will return an error.
		_, err = ssh.ParsePrivateKey(key)
		if err != nil {
			continue
		}
		keyfiles = append(keyfiles, keyPath)
	}

	// start building the command
	opts := make([]string, 0, 4)
	// no terminal
	opts = append(opts, "-nNT")
	if verbose {
		opts = append(opts, "-v")
	}
	// identity files
	for _, key := range keyfiles {
		opts = append(opts, "-i"+key)
	}

	// socket location
	opts = append(opts, "-L"+socket+":/var/run/docker.sock")
	// host
	opts = append(opts, "docker@"+host)

	cmd := exec.Command("ssh", opts...)
	// wire up the command outputs to our ouputs
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// set up channel for stop signals
	signals := make(chan os.Signal, 1)
	// register for SIGINT and SIGTERM, this is what we will die on
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	// start the command
	cmd.Start()
	// tell the user how we're connecting
	fmt.Printf("remote docker server is listening locally at %v\n", socket)
	// TODO(dperny) print how to do configure docker daemon for this
	// wait for a signal
	sig := <-signals
	// pass it down to the ssh command
	cmd.Process.Signal(sig)
	// clean up the left-over socket
	err = os.Remove(socket)
	return err
}

func init() {
	attachCmd.Flags().BoolP("verbose", "v", false, "start ssh in verbose mode (for debugging)")
	attachCmd.Flags().String("socket", "", "the location to open the docker socket")
}
