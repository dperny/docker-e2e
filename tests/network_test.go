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

	// http is used to test network endpoints
	"net/http"

	// docker api
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
)

// tests the load balancer for services with public endpoints
func TestNetworkExternalLb(t *testing.T) {
	// TODO(dperny): there are debugging statements commented out. remove them.
	t.Parallel()
	name := "TestNetworkExternalLb"
	// create a client
	cli, err := GetClient()
	assert.NoError(t, err, "Client creation failed")

	replicas := 3
	// pass literal 3 so we don't have to cast
	spec := CannedServiceSpec(name, 3, name)
	// use nginx
	spec.TaskTemplate.ContainerSpec.Image = "dperny/docker-sample-nginx"
	spec.TaskTemplate.ContainerSpec.Command = nil
	// expose a port
	spec.EndpointSpec = &swarm.EndpointSpec{
		Mode: swarm.ResolutionModeVIP,
		Ports: []swarm.PortConfig{
			{
				Protocol:   swarm.PortConfigProtocolTCP,
				TargetPort: 80,
			},
		},
	}

	// create the service
	service, err := cli.ServiceCreate(context.Background(), spec, types.ServiceCreateOptions{})
	assert.NoError(t, err, "Error creating service")
	assert.NotNil(t, service, "Resp is nil for some reason")
	assert.NotZero(t, service.ID, "serviceonse ID is zero, something is amiss")

	// now make sure the service comes up
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	scaleCheck := ScaleCheck(service.ID, cli)
	err = WaitForConverge(ctx, 1*time.Second, scaleCheck(ctx, 3))
	assert.NoError(t, err)

	var published uint32
	full, _, err := cli.ServiceInspectWithRaw(context.TODO(), service.ID)
	assert.NoError(t, err, "Error getting newly created service")
	for _, port := range full.Endpoint.Ports {
		if port.TargetPort == 80 {
			published = port.PublishedPort
		}
	}
	port := fmt.Sprintf(":%v", published)

	// create a context, and also grab the cancelfunc
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

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
	go func() {
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
					resp, err := client.Get("http://" + endpoint + port)
					if err != nil {
						// TODO(dperny) properly handle error
						// fmt.Printf("error: %v", err)
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
					fmt.Printf("saw %v\n", name)

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
	}()

	// function to check if we've been LB'd to all containers
	checkComplete := func() error {
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

	err = WaitForConverge(ctx, time.Second, checkComplete)
	// cancel the context to stop polling
	cancel()

	mu.Lock()
	fmt.Printf("%v\n", containers)
	mu.Unlock()

	assert.NoError(t, err)

	CleanTestServices(context.Background(), cli, name)
}
