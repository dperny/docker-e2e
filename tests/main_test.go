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

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
)

var testUUID string

func prepareTestImages(cli *client.Client) error {
	name := "prep"

	// this isn't a test, it's just setup code. use a flat 2 minutes for the
	// whole thing.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	nodes, err := cli.NodeList(ctx, types.NodeListOptions{})
	if err != nil {
		return err
	}
	replicas := len(nodes)

	spec := CannedServiceSpec(name, 0)
	// NetworkTestImage is defined in network_test.go
	spec.TaskTemplate.ContainerSpec.Image = NetworkTestImage
	spec.Mode = swarm.ServiceMode{Global: &swarm.GlobalService{}}

	service, err := cli.ServiceCreate(ctx, spec, types.ServiceCreateOptions{})
	if err != nil {
		return err
	}
	defer CleanTestServices(context.TODO(), cli, name)

	return WaitForConverge(ctx, time.Second, ScaleCheck(service.ID, cli)(ctx, replicas))
}

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

	err = prepareTestImages(cli)
	if err != nil {
		fmt.Printf("error prepping test images: %v", err)
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
