package dockere2e

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"unsafe"

	"github.com/satori/go.uuid"
)

var test_uuid string

// TODO(dperny) hidden field, maintenance nightmare
// Copied from testing.M
type _M struct {
	matchString func(pat, str string) (bool, error)
	tests       []testing.InternalTest
	benchmarks  []testing.InternalBenchmark
	examples    []testing.InternalExample
}

func TestMain(m *testing.M) {
	// gotta call this at the start or NONE of the flags work
	flag.Parse()

	// get the tests
	tests := (*_M)(unsafe.Pointer(m)).tests

	// make channels for control
	cancel := make(chan struct{})
	interrupt := make(chan os.Signal, 1)

	// go over all of the tests
	for i := range tests {
		// get the testing function
		f := tests[i].F
		// now, wrap the testing functions.
		tests[i].F = func(t *testing.T) {
			// we make a channel that signals test completion
			done := make(chan struct{})
			// run the test in its own goroutine
			go func() {
				f(t)
				// signal the parent goroutine that the test exited normally
				close(done)
			}()
			select {
			// if we get an interrupt, immediately Fatal the test, stopping it
			case <-interrupt:
				if cancel != nil {
					close(interrupt)
					cancel = nil
					t.Fatal("interrupted by signal")
				} else {
					t.SkipNow()
				}
			case <-done:
			case <-cancel:
			}
		}
	}

	// register the interrupt channel as the signal handler
	signal.Notify(interrupt, syscall.SIGINT)

	// we need a client
	cli, err := GetClient()
	if err != nil {
		os.Exit(1)
	}

	// run the tests, save the exit
	exit := m.Run()

	// after the tests have been run (or canceled) clean up any cruft
	CleanTestServices(context.Background(), cli)

	// and then bow out
	os.Exit(exit)
}

// returns the Uuid that identifies this test
func Uuid() string {
	return test_uuid
}

func init() {
	test_uuid = uuid.NewV4().String()
}
