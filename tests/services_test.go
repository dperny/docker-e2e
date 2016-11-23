package dockere2e

import (
	// basic imports
	"context"
	"testing"
	"time"

	// assertions are nice, let's do more of those
	"github.com/stretchr/testify/assert"
	// Engine API imports for talking to the docker engine
	"github.com/docker/docker/api/types"
)

func TestServicesList(t *testing.T) {
	t.Parallel()
	cli, err := GetClient()

	assert.NoError(t, err, "Client creation failed")

	// list all services with the "TestServiceList" label
	opts := types.ServiceListOptions{Filters: GetTestFilter("TestServiceList")}
	services, err := cli.ServiceList(context.Background(), opts)
	// there shouldn't be any services with that label
	assert.NoError(t, err, "error listing service")
	assert.Empty(t, services)
}

func TestServicesCreate(t *testing.T) {
	t.Parallel()
	// label name for cleanup later
	name := "TestServicesCreate"

	cli, err := GetClient()

	assert.NoError(t, err, "Client creation failed")
	// create a spec for a task named TestServicesCreate labeled the same, with 3 replicas
	serviceSpec := CannedServiceSpec(name, 3, name)

	// first, verify that the server responds as expected
	resp, err := cli.ServiceCreate(context.Background(), serviceSpec, types.ServiceCreateOptions{})
	assert.NoError(t, err, "Error creating service")
	assert.NotNil(t, resp, "Resp is nil for some reason")
	assert.NotZero(t, resp.ID, "response ID shouldn't be zero")

	// now make sure we can call back and get the service
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = WaitForConverge(ctx, 2*time.Second, func() error {
		_, _, err := cli.ServiceInspectWithRaw(ctx, resp.ID)
		if err != nil {
			return err
		}
		return nil
	})
	assert.NoError(t, err)

	// clean up our service
	CleanTestServices(context.Background(), cli, name)
}

func TestServicesScale(t *testing.T) {
	t.Parallel()
	name := "TestServicesScale"

	cli, err := GetClient()
	assert.NoError(t, err, "could not create client")

	// create a new service
	serviceSpec := CannedServiceSpec(name, 1, name)
	service, err := cli.ServiceCreate(context.Background(), serviceSpec, types.ServiceCreateOptions{})
	assert.NoError(t, err, "error creating service")

	// get a new scale check generator
	scaleCheck := ScaleCheck(service.ID, cli)

	// check that it converges to 1 replica
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	err = WaitForConverge(ctx, 2*time.Second, scaleCheck(ctx, 1))
	assert.NoError(t, err)

	// get the full spec to make changes
	full, _, err := cli.ServiceInspectWithRaw(context.Background(), service.ID)
	// more replicas
	var replicas uint64 = 3
	full.Spec.Mode.Replicated.Replicas = &replicas
	// send the update
	version := full.Meta.Version
	_, err = cli.ServiceUpdate(context.Background(), service.ID, version, full.Spec, types.ServiceUpdateOptions{})
	assert.NoError(t, err)

	// check that it converges to 3 replicas
	ctx, _ = context.WithTimeout(context.Background(), 30*time.Second)
	err = WaitForConverge(ctx, 2*time.Second, scaleCheck(ctx, 3))
	assert.NoError(t, err)

	// clean up after
	CleanTestServices(context.Background(), cli, name)
}

/*
func TestServicesRollingUpdateSucceed(t *testing.T) {
	// TODO(dperny): this test sucks and is a hack, make it better
	t.SkipNow()
	name := "TestServicesRollingUpdateSucceed"

	// TODO(dperny): come up with a function for the next 9 lines? i use it over and over
	// get a client
	cli, err := GetClient()
	assert.NoError(t, err, "could not create client")

	// create a service, 6 replicas
	serviceSpec := CannedServiceSpec(name, 6, name)
	service, err := cli.ServiceCreate(context.Background(), serviceSpec, types.ServiceCreateOptions{})
	assert.NoError(t, err, "error creating service")

	// new scale check generator
	scaleCheck := ScaleCheck(service.ID, cli)

	// create a context for converge timeout
	ctx, _ := context.WithTimeout(context.Background(), 60*time.Second)
	// wait until we've converged all 6 replicas to running state
	err = WaitForConverge(ctx, 500*time.Millisecond, scaleCheck(ctx, 6))
	assert.NoError(t, err)

	// now, update the service to a new image
	// get the full service spec from the cluster
	full, _, err := cli.ServiceInspectWithRaw(context.Background(), service.ID)
	// set a new image
	full.Spec.TaskTemplate.ContainerSpec.Image = "alpine"
	full.Spec.TaskTemplate.ContainerSpec.Command = []string{"ping", "localhost"}
	// and set update parameters for 2 at a time, 5 seconds between them
	full.Spec.UpdateConfig = &swarm.UpdateConfig{
		Parallelism: 2,
		Delay:       5 * time.Second,
	}
	// TODO(dperny): segfaults if done like this. is it because updateconfig doesn't exist?
	// full.Spec.UpdateConfig.Parallelism = 2
	// full.Spec.UpdateConfig.Delay = 5 * time.Second
	_, err = cli.ServiceUpdate(context.Background(), service.ID, full.Meta.Version, full.Spec, types.ServiceUpdateOptions{})
	assert.NoError(t, err)

	// we should see updates in 2s, 3 separate sets
	for i := 2; i <= 6; i = i + 2 {
		// 5 second timeout because after 5 seconds, the tasks will roll over
		ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
		err = WaitForConverge(ctx, 500*time.Millisecond, func() error {
			// get the task list, check for errors
			tasks, err := GetServiceTasks(context.Background(), cli, service.ID)
			if err != nil {
				return err
			}
			if l := len(tasks); l != 6 {
				return errors.Errorf("expected %v tasks got %v", 6, l)
			}
			// go through the tasks, counting the updated ones
			updated := 0
			for _, task := range tasks {
				if task.Spec.ContainerSpec.Image == "alpine" && task.Status.State == swarm.TaskStateRunning {
					updated = updated + 1
				}
			}
			// check that we have the same number of updated tasks that we should
			if updated != i {
				return errors.Errorf("expected %v tasks updated at this stage, got %v", i, updated)
			}
			return nil
		})
		// check at each stage for convergence errors
		assert.NoError(t, err)
	}

	// clean up after
	CleanTestServices(context.Background(), cli, name)
}
*/
