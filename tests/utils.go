package dockere2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
)

const E2EServiceLabel = "e2etesting"

func GetClient() (*client.Client, error) {
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	return cli, nil
}

// CleanTestServices removes all e2etesting services with the specified labels
func CleanTestServices(ctx context.Context, cli *client.Client, labels ...string) error {
	// create a new filter for our test label
	f := GetTestFilter(labels...)
	opts := types.ServiceListOptions{
		Filters: f,
	}
	// get the services with that label
	services, err := cli.ServiceList(ctx, opts)
	if err != nil {
		return err
	}

	// delete all of them
	for _, service := range services {
		cli.ServiceRemove(ctx, service.ID)
	}

	return nil
}

// truncName truncates the name to 63 characters, or 62 if the last character is a dash.
func truncName(name string) string {
	// we don't need to truncate anything less than 63 characters
	if len(name) < 63 {
		return name
	}
	// take only the first 63 characters, and trim off any dashes.
	return strings.Trim(name[0:63], "-")
}

func getUniqueName(name string) string {
	return truncName(name + UUID())
}

// CannedServiceSpec returns a ready-to-go service spec with name and replicas
func CannedServiceSpec(cli *client.Client, name string, replicas uint64, command, nw []string, labels ...string) swarm.ServiceSpec {
	// first create the canned spec
	spec := swarm.ServiceSpec{
		Annotations: swarm.Annotations{
			Name: truncName(name + UUID()),
			Labels: map[string]string{
				// the pre-mangled service name is a raw key-only label.
				name:            "",
				E2EServiceLabel: "true",
				"uuid":          UUID(),
			},
		},
		TaskTemplate: swarm.TaskSpec{
			ContainerSpec: swarm.ContainerSpec{
				Image: GetSelfImage(cli),
			},
		},
		Mode: swarm.ServiceMode{Replicated: &swarm.ReplicatedService{Replicas: &replicas}},
		EndpointSpec: &swarm.EndpointSpec{
			Ports: []swarm.PortConfig{
				{
					Protocol:   "tcp",
					TargetPort: 80,
				},
			},
		},
	}

	if command != nil {
		spec.TaskTemplate.ContainerSpec.Command = command
	} else {
		spec.TaskTemplate.ContainerSpec.Command =
			[]string{"util", "test-server"}
	}
	if nw != nil {
		networks := []swarm.NetworkAttachmentConfig{}
		for _, n := range nw {
			networks = append(networks,
				swarm.NetworkAttachmentConfig{Target: n})
		}
		spec.TaskTemplate.Networks = networks
	}

	// then, add labels
	for _, label := range labels {
		// TODO(dperny): allow labels in form key=value?
		spec.Annotations.Labels[label] = ""
	}

	return spec
}

// WaitForConverge does test every poll
// returns nothing if test returns nothing, or test's error after context is done
//
// make sure that context is either canceled or given a timeout; if it isn't,
// test will run until half life 3 is released.
//
// if an irrecoverable error is noticed during the test function, calling the
// context's cancel func from inside the test can be used to abort the test
// before the timeout
func WaitForConverge(ctx context.Context, poll time.Duration, test func() error) error {
	// create a ticker and a timer
	r := time.NewTicker(poll)
	// don't forget to close this thing
	// do we have to close this thing? idk
	defer r.Stop()

	var err error
	for {
		select {
		case <-ctx.Done():
			// if the context is done, just return whatever our last saved error was
			return errors.Wrap(err, "failed to converge")
		case <-r.C:
			// do test, save the error
			nextErr := test()
			// TODO(dperny) ughhhhhhhhhhhhhhhhhhhhh
			// if the context times out during a call to the docker api, we
			// will get context deadline exceeded which could mask the real
			// error. in this case, if we already have an error, discard the
			// the deadline exceeded error

			// if we haven't caught an error yet, keep this one no matter what
			// OR, if nextErr is nil.
			if err == nil || nextErr == nil {
				err = nextErr
			}

			// if we have already caught an error, and we just caught another one
			if err != nil && nextErr != nil {
				// check if it's a not context deadline exceeded error
				if !strings.Contains(nextErr.Error(), "context deadline exceeded") {
					// if it isn't, then it's useful; keep it
					err = nextErr
				}
				// if it was context deadline exceed, go with whatever the last
				// error was, but wrap it to tell the user
				err = errors.Wrap(err, "context deadline exceeded. last recorded failure condition wrapped.")
			}
		}
		// if there is no error, we're done
		if err == nil {
			return nil
		}
	}
}

// GetServiceTasks returns all of the tasks associated with a the service
func GetServiceTasks(ctx context.Context, cli *client.Client, serviceID string) ([]swarm.Task, error) {
	// get the default filter
	filterArgs := GetTestFilter()
	// all of the tasks that we want to be running
	filterArgs.Add("desired-state", "running")
	filterArgs.Add("desired-state", "ready")
	// on the service we're requesting
	filterArgs.Add("service", serviceID)
	return cli.TaskList(ctx, types.TaskListOptions{Filters: filterArgs})
}

// GetTestFilter creates a default filter for labels
// Always adds the E2EServiceLabel, plus some user-defined labels.
// if you need more fitlers, add them to the returned value.
func GetTestFilter(labels ...string) filters.Args {
	filterArgs := filters.NewArgs()
	filterArgs.Add("label", E2EServiceLabel)
	filterArgs.Add("label", "uuid="+UUID())
	for _, l := range labels {
		filterArgs.Add("label", l)
	}
	return filterArgs
}

// ScaleCheck returns a generator for scale checking functions. Pass in the
// service and client once to get the scale checker generator. Pass the context
// and replicas to that to get a scale checker
func ScaleCheck(serviceID string, cli *client.Client) func(context.Context, int) func() error {
	return func(ctx context.Context, replicas int) func() error {
		return func() error {
			// get all of the tasks for the service
			tasks, err := GetServiceTasks(ctx, cli, serviceID)
			if err != nil {
				return errors.Wrap(err, "failed to get service tasks")
			}
			// check for correct number of tasks
			if t := len(tasks); t != replicas {
				return errors.Errorf("wrong number of tasks, got %v expected %v", t, replicas)
			}
			// verify that all tasks are in the RUNNING state
			for _, task := range tasks {
				if task.Status.State != swarm.TaskStateRunning {
					return errors.New("a task is not yet running")
				}
			}
			// if all of the above checks out, service has converged
			return nil
		}
	}
}

// GetNodeIps returns a list of all node IP addresses in the cluster
func GetNodeIps(cli *client.Client) ([]string, error) {
	nodes, err := cli.NodeList(context.TODO(), types.NodeListOptions{})
	if err != nil {
		return nil, err
	}
	// standard cluster is like 3 managers 5 workers, so 8 is a good start
	ips := make([]string, 0, 8)
	for _, node := range nodes {
		ip := node.Status.Addr
		// Prefer the manager IP if present
		if node.ManagerStatus != nil && node.ManagerStatus.Addr != "" {
			ip, _, err = net.SplitHostPort(node.ManagerStatus.Addr)
			if err != nil {
				return nil, fmt.Errorf("malformed node.ManagerStatus.Addr: %s", err)
			}
		}
		if ip == "" {
			return nil, errors.New("some node didn't have an associated IP")
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// GetSelfImage returns the image name or ID of the current running environment
// or the image that the outter rigging expects to use for nested containers
// If we're unable to determine the image, "dockerswarm/e2e:latest" is returned
// as a sensible default suitable for running child container scnearios
func GetSelfImage(cli *client.Client) string {
	imageName := os.Getenv("TEST_IMAGE_NAME")
	if imageName == "" {
		imageName = "dockerswarm/e2e:latest"
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return imageName
	}

	args := filters.NewArgs()
	args.Add("id", hostname)
	containers, err := cli.ContainerList(context.TODO(), types.ContainerListOptions{Filters: args})
	if err == nil && len(containers) > 0 {
		return containers[0].ImageID
	}
	return imageName
}

// serviceLookup resolves the passed name by using the test server's /service-discovery endpoint
func serviceLookup(endpoint, port, qName string) ([]net.IP, error) {
	tr := &http.Transport{}
	client := &http.Client{Transport: tr, Timeout: time.Duration(5 * time.Second)}

	resp, err := client.Get("http://" + endpoint + port + "/service-discovery?v4=" + qName)
	if err != nil {
		return nil, fmt.Errorf("Accessing /service-discovery endpoint failed")
	}
	defer resp.Body.Close()

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Reading /service-discovery response failed")
	}
	ip := []net.IP{}
	err = json.Unmarshal(result, &ip)
	return ip, err
}

// getNodeIPPort fetchces one cluster member IP and published port for the given targetPort
func getNodeIPPort(cli *client.Client, c context.Context, id string, targetPort uint32) (string, uint32, error) {
	ips, err := GetNodeIps(cli)
	if err != nil || len(ips) == 0 {
		return "", 0, fmt.Errorf("error listing nodes to get IP")
	}

	full, _, err := cli.ServiceInspectWithRaw(c, id, types.ServiceInspectOptions{})
	if err != nil {
		return "", 0, fmt.Errorf("error getting service")
	}
	for _, port := range full.Endpoint.Ports {
		if port.TargetPort == targetPort {
			return ips[0], port.PublishedPort, nil
		}
	}
	return "", 0, fmt.Errorf("error getting PublishedPort for targetPort %d", targetPort)
}
