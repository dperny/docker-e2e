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

// TestServicesCreate is the prototypical test. it should remain well-
// documented and serve as the starting point for any new developer that wants
// to write an e2e test. It tests that a service is successfully created.
func TestServicesCreate(t *testing.T) {
	// if your test can at all be run in parallel, do so.
	t.Parallel()

	// Create a name to use for this test. It will be passed as the name for
	// most operations. This should be done even if you're creating multiple
	// services; you can pass this name as a label later, which aids cleanup
	name := "TestServicesCreate"

	// Create a context for the test. This test should complete in under a
	// minute. If this context lapses, all of the API calls will just quick
	// return, saving time. This should also be used as the parent context for
	// any subcontexts you create.
	testContext, _ := context.WithTimeout(context.Background(), time.Minute)

	// Use the same client for the whole test. Verify that your client has been
	// created properly.
	cli, err := GetClient()
	assert.NoError(t, err, "Client creation failed")

	// Create a service spec to use. Your service specs should always be
	// created with CannedServiceSpec. This function gives you a service spec
	// with sensible default fields, as well as labels that assist in cleaning
	// up. In addition, CannedServiceSpec mangles the name and adds the uuid
	// label that we rely on to isolate this particular instance of the tests
	// from any other instance that may be running
	serviceSpec := CannedServiceSpec(name, 3)

	// Now, do an API call. Pass testContext, which will take care of the
	// timeout for us.
	resp, err := cli.ServiceCreate(testContext, serviceSpec, types.ServiceCreateOptions{})
	// Always make sure that the call completed as expected: no errors, non-nil
	// response, and non-zero ID.
	assert.NoError(t, err, "Error creating service")
	assert.NotNil(t, resp, "Resp is nil for some reason")
	assert.NotZero(t, resp.ID, "response ID shouldn't be zero")

	// Take the service ID. You should ALWAYS refer to services internally by
	// their ID and not by their name or any other features. Names are mangled,
	// labels may be changed, and any other number of identifiers could be
	// munged under the hood to facilitate "namespacing" the test, so the
	// service ID should be the sole point of reference for a particular
	// service whenever possible.
	serviceID := resp.ID

	// Here is one of the magicky parts: WaitForConverge. It should be used
	// whenever you perform an operation changing cluster state, because those
	// operations are _not_ synchronous. It takes a Context that provides a
	// timeout, a polling period, and a function returning only an error. This
	// function will be called each polling period, and if it returns nil, we
	// will assume the test has succeeded. If the context times out, the
	// polling will stop and and the error returned on the last poll of the
	// function will be returned
	ctx, _ := context.WithTimeout(testContext, 10*time.Second)
	err = WaitForConverge(ctx, 2*time.Second, func() error {
		// in this case, we're just waiting for inspect to return no errors,
		// which should happen almost instantly. More complicated checks will
		// have more complicated functions
		_, _, err := cli.ServiceInspectWithRaw(ctx, serviceID)
		if err != nil {
			return err
		}
		return nil
	})
	assert.NoError(t, err)

	// Clean up the test services. You should call this at the end of your
	// test to clean up any services that belong to it. You MUST pass the name,
	// or this call will clean up EVERYBODY's test services and cause
	// everything to break. This function handles internally, under the hood,
	// the uuid label-based isolation, so you don't have to worry about it.
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
