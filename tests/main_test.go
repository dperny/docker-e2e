package dockere2e

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/satori/go.uuid"
)

var testUUID string

func TestMain(m *testing.M) {
	// gotta call this at the start or NONE of the flags work
	flag.Parse()

	// interrupt and finished handler
	interrupt := make(chan os.Signal, 1)
	done := make(chan struct{})

	// register the interrupt channel as the signal handler
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	// we need a client
	cli, err := GetClient()
	if err != nil {
		os.Exit(1)
	}

	var exit int
	// spin up a goroutine to clean up on interrupt
	go func() {
		select {
		case <-interrupt:
		case <-done:
		}
		// after the tests have been run (or canceled) clean up any cruft
		CleanTestServices(context.Background(), cli)
		os.Exit(exit)
	}()

	fmt.Printf("Running tests with UUID %v\n", UUID())
	// run the tests, save the exit
	exit = m.Run()
	// close the done channel to run cleanup

	// signal for cleanup
	close(done)
	// wait 10 seconds, then just hardquit. this might be too short,
	time.Sleep(10 * time.Second)
	fmt.Println("Cleaning took too long, dying.")

	os.Exit(exit)
}

// returns the Uuid that identifies this test
func UUID() string {
	return testUUID
}

func init() {
	testUUID = uuid.NewV4().String()
}
