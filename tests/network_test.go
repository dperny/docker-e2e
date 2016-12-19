package dockere2e

import (
	// basic imports
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"testing"
	"time"

	// testify
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pkg/errors"

	// http is used to test network endpoints
	"net/http"

	// docker api
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
)

const NetworkTestImage string = "dperny/httptest"

func pollEndpoint(ctx context.Context, endpoint string, containers map[string]int, mu *sync.Mutex) {
	for {
		select {
		case <-ctx.Done():
			// stop polling when ctx is done
			return
		default:
			// anonymous func to leverage defers
			func() {
				// TODO(dperny) consider breaking out into separate function
				// lock the mutex to synchronize access to the map
				mu.Lock()
				defer mu.Unlock()
				tr := &http.Transport{}
				client := &http.Client{Transport: tr, Timeout: time.Duration(5 * time.Second)}

				// poll the endpoint
				// TODO(dperny): this string concat is probably Bad
				resp, err := client.Get("http://" + endpoint)
				if err != nil {
					// TODO(dperny) properly handle error
					fmt.Printf("error polling endpoint: %v\n", err)
					return
				}

				// body text should just be the container id
				namebytes, err := ioutil.ReadAll(resp.Body)
				// docs say we have to close the body. defer doing so
				defer resp.Body.Close()
				if err != nil {
					// TODO(dperny) properly handle error
					return
				}
				name := strings.TrimSpace(string(namebytes))
				// fmt.Printf("saw %v\n", name)

				// if the container has already been seen, increment its count
				if count, ok := containers[name]; ok {
					containers[name] = count + 1
					// if not, add it as a new record with count 1
				} else {
					containers[name] = 1
				}
			}()
			// if we don't sleep, we'll starve the check function. we stop
			// just long enough for the system to schedule the check function
			// TODO(dperny): figure out a cleaner way to do this.
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// checkComplete returns a function that can be used to check if a network test
// has succeeded
func checkComplete(replicas int, containers map[string]int, mu *sync.Mutex, cancel context.CancelFunc) func() error {
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		c := len(containers)
		// check if we have too many containers (unlikely but possible)
		if c > replicas {
			// cancel the context, we have overshot and will never converge
			cancel()
			return fmt.Errorf("expected %v different container IDs, got %v", replicas, c)
		}
		// now check if we have too few
		if c < replicas {
			return fmt.Errorf("haven't seen enough different containers, expected %v got %v", replicas, c)
		}
		// now check that we've hit each container at least 2 times
		for name, count := range containers {
			if count < 2 {
				return fmt.Errorf("haven't seen container %v twice", name)
			}
		}
		// if everything so far passes, we're golden
		return nil
	}
}

func getServicePublishedPort(service *swarm.Service, target uint32) (uint32, error) {
	for _, port := range service.Endpoint.Ports {
		if port.TargetPort == target {
			return port.PublishedPort, nil
		}
	}
	return 0, errors.New("Could not find target port")
}

func cannedNetworkServiceSpec(name string, replicas uint64, labels ...string) swarm.ServiceSpec {
	spec := CannedServiceSpec(name, replicas, labels...)
	spec.TaskTemplate.ContainerSpec.Image = NetworkTestImage
	// TODO(dperny): explain in a comment why we set command to nil
	spec.TaskTemplate.ContainerSpec.Command = nil
	spec.EndpointSpec = &swarm.EndpointSpec{
		Mode: swarm.ResolutionModeVIP,
		Ports: []swarm.PortConfig{
			{
				Protocol:   swarm.PortConfigProtocolTCP,
				TargetPort: 80,
			},
		},
	}

	return spec
}

func TestNetworkExternalLbGlobal(t *testing.T) {
	// do parallel on every available test
	t.Parallel()
	// set up test-wide objects
	name := "TestNetworkExternalLbGlobal"
	testContext, testCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	// cancel the context to avoid leaking
	defer testCancel()

	// create a client
	cli, err := GetClient()
	require.NoError(t, err, "Client creation failed")

	// get the number of nodes. this will be our number of global tasks created
	nodes, err := cli.NodeList(testContext, types.NodeListOptions{})
	assert.NoError(t, err, "Node list failed")
	replicas := len(nodes)

	// get the spec
	spec := cannedNetworkServiceSpec(name, 0)
	spec.Mode = swarm.ServiceMode{Global: &swarm.GlobalService{}}

	//create the service and make sure it comes up
	service, err := cli.ServiceCreate(testContext, spec, types.ServiceCreateOptions{})
	require.NoError(t, err, "Error creating service")
	ctx, cancel := context.WithTimeout(testContext, 30*time.Second)
	scaleCheck := ScaleCheck(service.ID, cli)
	err = WaitForConverge(ctx, time.Second, scaleCheck(ctx, replicas))
	assert.NoError(t, err)
	cancel()

	// find the published port
	full, _, err := cli.ServiceInspectWithRaw(testContext, service.ID)
	assert.NoError(t, err, "Error inspecting service")
	published, err := getServicePublishedPort(&full, 80)
	require.NoError(t, err)
	port := fmt.Sprintf(":%v", published)

	// get a context for this portion of the test
	ctx, cancel = context.WithTimeout(testContext, 30*time.Second)

	containers := make(map[string]int)
	mu := new(sync.Mutex)

	ips, err := GetNodeIps(cli)
	assert.NoError(t, err, "error getting node ip")
	endpoint := ips[0]

	go pollEndpoint(ctx, endpoint+port, containers, mu)

	check := checkComplete(replicas, containers, mu, cancel)
	err = WaitForConverge(ctx, time.Second, check)
	assert.NoError(t, err)
	cancel()
}

// tests the load balancer for services with public endpoints
func TestNetworkExternalLbReplicated(t *testing.T) {
	// TODO(dperny): there are debugging statements commented out. remove them.
	t.Parallel()
	name := "TestNetworkExternalLbReplicated"
	testContext, testCancel := context.WithTimeout(context.Background(), time.Minute)
	// cancel the context to avoid leaking
	defer testCancel()
	// create a client
	cli, err := GetClient()
	assert.NoError(t, err, "Client creation failed")

	replicas := 3
	spec := cannedNetworkServiceSpec(name, uint64(replicas))

	// create the service
	service, err := cli.ServiceCreate(testContext, spec, types.ServiceCreateOptions{})
	assert.NoError(t, err, "Error creating service")
	assert.NotNil(t, service, "Resp is nil for some reason")
	assert.NotZero(t, service.ID, "serviceonse ID is zero, something is amiss")

	// now make sure the service comes up
	ctx, cancel := context.WithTimeout(testContext, 30*time.Second)
	scaleCheck := ScaleCheck(service.ID, cli)
	err = WaitForConverge(ctx, 1*time.Second, scaleCheck(ctx, 3))
	assert.NoError(t, err)
	// cancel context to avoid leaking
	cancel()

	full, _, err := cli.ServiceInspectWithRaw(testContext, service.ID)
	published, err := getServicePublishedPort(&full, 80)
	require.NoError(t, err)
	port := fmt.Sprintf(":%v", published)

	// create a context, and also grab the cancelfunc
	ctx, cancel = context.WithTimeout(testContext, 30*time.Second)

	// alright now comes the tricky part. we're gonna hit the endpoint
	// repeatedly until we get 3 different container ids, twice each.
	// if we hit twice each, we know that we've been LB'd around to each
	// instance. why twice? seems like a good number, idk. when i test LB
	// manually i just hit the endpoint a few times until i've seen each
	// container a couple of times

	// create a map to store all the containers we've seen
	containers := make(map[string]int)
	// create a mutex to synchronize access to this map
	mu := new(sync.Mutex)

	// select the network endpoint we're going to hit
	// list the nodes
	ips, err := GetNodeIps(cli)
	assert.NoError(t, err, "error listing nodes to get IP")
	assert.NotZero(t, ips, "no node ip addresses were returned")
	// take the first node
	endpoint := ips[0]

	// first we need a function to poll containers, and let it run
	go pollEndpoint(ctx, endpoint+port, containers, mu)

	// function to check if we've been LB'd to all containers
	check := checkComplete(replicas, containers, mu, cancel)

	err = WaitForConverge(ctx, time.Second, check)
	// cancel the context to stop polling
	cancel()

	assert.NoError(t, err)

	CleanTestServices(testContext, cli, name)
}

func TestNetworkInternalLb(t *testing.T) {
	t.Parallel()
	name := "TestNetworkInternalLb"
	testContext, testCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	// cancel the context to avoid leaking
	defer testCancel()

	// create a client
	cli, err := GetClient()
	require.NoError(t, err, "Client creation failed")

	// create a network
	_, err = cli.NetworkCreate(testContext, MangleObjectName(name), types.NetworkCreate{
		Driver: "overlay",
	})
	require.NoError(t, err, "couldn't create network")

	// create the internal network service
	replicas := 6
	spec := cannedNetworkServiceSpec(name+"Internal", uint64(replicas))
	spec.EndpointSpec = nil
	spec.Networks = []swarm.NetworkAttachmentConfig{{Target: MangleObjectName(name)}}
	internal, err := cli.ServiceCreate(testContext, spec, types.ServiceCreateOptions{})
	require.NoError(t, err, "error creating internal service")
	ctx, cancel := context.WithTimeout(testContext, 30*time.Second)
	err = WaitForConverge(ctx, time.Second, ScaleCheck(internal.ID, cli)(ctx, replicas))
	assert.NoError(t, err)
	cancel()

	extReplicas := 1
	// create the external service
	externalSpec := cannedNetworkServiceSpec(name+"External", uint64(extReplicas))
	externalSpec.Networks = []swarm.NetworkAttachmentConfig{{Target: MangleObjectName(name)}}
	external, err := cli.ServiceCreate(testContext, externalSpec, types.ServiceCreateOptions{})
	require.NoError(t, err, "error creating external service")
	ctx, cancel = context.WithTimeout(testContext, 30*time.Second)
	err = WaitForConverge(ctx, time.Second, ScaleCheck(external.ID, cli)(ctx, extReplicas))
	assert.NoError(t, err)
	cancel()

	// get the published port
	full, _, err := cli.ServiceInspectWithRaw(testContext, external.ID)
	assert.NoError(t, err)
	published, err := getServicePublishedPort(&full, 80)
	require.NoError(t, err)
	port := fmt.Sprintf(":%v", published)

	ips, _ := GetNodeIps(cli)
	// TODO(dperny) error check
	endpoint := ips[0] + port + "/proxy/" + spec.Name

	containers := make(map[string]int)
	mu := new(sync.Mutex)
	ctx, cancel = context.WithTimeout(testContext, 30*time.Second)

	go pollEndpoint(ctx, endpoint, containers, mu)
	check := checkComplete(replicas, containers, mu, cancel)
	err = WaitForConverge(ctx, time.Second, check)
	assert.NoError(t, err)
	cancel()
	// remove network
	cli.NetworkRemove(testContext, MangleObjectName(name))

	fmt.Printf("%v\n", containers)
}
