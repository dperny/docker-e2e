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
	testContext, _ := context.WithTimeout(context.Background(), time.Minute)

	assert.NoError(t, err, "Client creation failed")

	// list all services with the "TestServiceList" label
	opts := types.ServiceListOptions{Filters: GetTestFilter("TestServiceList")}
	services, err := cli.ServiceList(testContext, opts)
	// there shouldn't be any services with that label
	assert.NoError(t, err, "error listing service")
	assert.Empty(t, services)
}

func TestServicesCreate(t *testing.T) {
	t.Parallel()
	// label name for cleanup later
	name := "TestServicesCreate"
	testContext, _ := context.WithTimeout(context.Background(), time.Minute)

	cli, err := GetClient()

	assert.NoError(t, err, "Client creation failed")
	// create a spec for a task named TestServicesCreate labeled the same, with 3 replicas
	serviceSpec := CannedServiceSpec(name, 3)

	// first, verify that the server responds as expected
	resp, err := cli.ServiceCreate(testContext, serviceSpec, types.ServiceCreateOptions{})
	assert.NoError(t, err, "Error creating service")
	assert.NotNil(t, resp, "Resp is nil for some reason")
	assert.NotZero(t, resp.ID, "response ID shouldn't be zero")

	// now make sure we can call back and get the service
	ctx, _ := context.WithTimeout(testContext, 10*time.Second)
	err = WaitForConverge(ctx, 2*time.Second, func() error {
		_, _, err := cli.ServiceInspectWithRaw(ctx, resp.ID)
		if err != nil {
			return err
		}
		return nil
	})
	assert.NoError(t, err)

	// clean up our service
	CleanTestServices(testContext, cli, name)
}

func TestServicesScale(t *testing.T) {
	t.Parallel()
	name := "TestServicesScale"
	testContext, _ := context.WithTimeout(context.Background(), time.Minute)

	cli, err := GetClient()
	assert.NoError(t, err, "could not create client")

	// create a new service
	serviceSpec := CannedServiceSpec(name, 1)
	service, err := cli.ServiceCreate(testContext, serviceSpec, types.ServiceCreateOptions{})
	assert.NoError(t, err, "error creating service")

	// get a new scale check generator
	scaleCheck := ScaleCheck(service.ID, cli)

	// check that it converges to 1 replica
	ctx, _ := context.WithTimeout(testContext, 30*time.Second)
	err = WaitForConverge(ctx, 2*time.Second, scaleCheck(ctx, 1))
	assert.NoError(t, err)

	// get the full spec to make changes
	full, _, err := cli.ServiceInspectWithRaw(testContext, service.ID)
	// more replicas
	var replicas uint64 = 3
	full.Spec.Mode.Replicated.Replicas = &replicas
	// send the update
	version := full.Meta.Version
	_, err = cli.ServiceUpdate(testContext, service.ID, version, full.Spec, types.ServiceUpdateOptions{})
	assert.NoError(t, err)

	// check that it converges to 3 replicas
	ctx, _ = context.WithTimeout(testContext, 30*time.Second)
	err = WaitForConverge(ctx, 2*time.Second, scaleCheck(ctx, 3))
	assert.NoError(t, err)

	// clean up after
	CleanTestServices(testContext, cli, name)
}
