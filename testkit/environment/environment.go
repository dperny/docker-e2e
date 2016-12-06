package environment

import (
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
)

func List(sess *session.Session) ([]*cloudformation.Stack, error) {
	cf := cloudformation.New(sess)

	stacks := []*cloudformation.Stack{}

	input := &cloudformation.DescribeStacksInput{}
	for {
		resp, err := cf.DescribeStacks(input)
		if err != nil {
			return nil, err
		}

		for _, stack := range resp.Stacks {
			// stack.Tags is a list of Tag structs, which have fields
			// `Key *string` and `Value *string`. yeah, really.
			for _, tag := range stack.Tags {
				// TODO(dperny) this is ugly, there must be a better way
				if aws.StringValue(tag.Key) == "docker" && aws.StringValue(tag.Value) == "e2e" {
					stacks = append(stacks, stack)
				}
			}

		}

		if resp.NextToken == nil {
			return stacks, nil
		}
		input.NextToken = resp.NextToken
	}
}

// Purge deletes stacks older than `ttl`
func Purge(sess *session.Session, ttl time.Duration) error {
	stacks, err := List(sess)
	if err != nil {
		return err
	}

	for _, stack := range stacks {
		// Skip stacks that haven't yet expired (recently created)
		creation := *stack.CreationTime
		expiration := creation.Add(ttl)
		if expiration.After(time.Now().UTC()) {
			logrus.Warnf("Skipping %s (created %v ago)", *stack.StackName, time.Now().UTC().Sub(creation))
			continue
		}

		logrus.Infof("Cleaning up %s (created %v ago)", *stack.StackName, time.Now().UTC().Sub(creation))
		env := New(*(stack.StackId), sess)
		err := env.Destroy()
		if err != nil {
			logrus.Errorf("Failed to delete %s: %v", *stack.StackName, err)
		}
	}

	return nil
}

// Environment represents a testing cluster, including a CloudFormation stack
// and SSH client
type Environment struct {
	id      string
	cf      *cloudformation.CloudFormation
	session *session.Session
	client  *ssh.Client
}

// New returns a new environment
func New(id string, sess *session.Session) *Environment {
	return &Environment{
		id:      id,
		cf:      cloudformation.New(sess),
		session: sess,
	}
}

// Destroy deletes the CloudFormation stack associated with the environment
func (c *Environment) Destroy() error {
	_, err := c.cf.DeleteStack(&cloudformation.DeleteStackInput{
		StackName: aws.String(c.id),
	})
	return err
}

// SSHEndpoint returns an ssh endpoint of the CloudFormation stack
func (c *Environment) SSHEndpoint() (string, error) {
	// get a list of all of the manager ips
	ips, err := c.ManagerIPs()
	if err != nil {
		return "", err
	}

	// we should never get 0 ip addresses back from ManagerIPs without error,
	// but just in case, we should check to avoid segfaulting
	if len(ips) == 0 {
		return "", errors.New("no ip addresses found")
	}

	// TODO(dperny) should we append the port? i think probably not
	return ips[rand.Intn(len(ips))], nil
}

// ManagerIPs returns a list of IP addresses of manager nodes
func (c *Environment) ManagerIPs() ([]string, error) {
	output, err := c.cf.DescribeStacks(&cloudformation.DescribeStacksInput{
		StackName: aws.String(c.id),
	})
	if err != nil {
		return nil, err
	}
	if len(output.Stacks) != 1 {
		return nil, errors.New("stack not found")
	}
	stack := output.Stacks[0]

	// create a new EC2 client so we can list EC2 instances
	ec2client := ec2.New(c.session)

	// use the swarm info as filters
	//   swarm-stack-id: from describe stack
	//   swarm-node-type: manager
	// if the above API ever changes (lol) we can use these two tags instead:
	//   aws:cloudformation:stack-id: from describe stack
	//   aws:cloudformation:logical-id: ManagerAsg
	input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("tag:swarm-stack-id"),
				Values: []*string{stack.StackId},
			},
			&ec2.Filter{
				Name:   aws.String("tag:swarm-node-type"),
				Values: []*string{aws.String("manager")},
			},
		},
	}

	// slice of ip addresses. we can expect at least 3, probably, so 3 is a
	// good starting value
	ips := []string{}
	// loop until we have no next page
	for {
		// do the api call, check for errors. duh.
		resp, err := ec2client.DescribeInstances(input)
		if err != nil {
			return nil, err
		}

		// instances may or may not belong to the same reservation. we don't
		// care, and we must iterate through both together as a rule
		for _, res := range resp.Reservations {
			for _, instance := range res.Instances {
				ips = append(ips, *instance.PublicIpAddress)
			}
		}

		if resp.NextToken == nil {
			break
		}
		// set the next token, in case our response has multiple pages
		input.NextToken = resp.NextToken
	}

	// make sure we actually have ip addresses, so that we don't just return
	// emptystring and no error.
	if len(ips) == 0 {
		return nil, errors.New("unable to retrieve SSH endpoint, found no managers")
	}

	return ips, nil
}

func (c *Environment) loadSSHKeys() (ssh.AuthMethod, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	keyDir := filepath.Join(usr.HomeDir, "/.ssh/")
	keys, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return nil, err
	}

	signers := []ssh.Signer{}
	for _, f := range keys {
		keyPath := filepath.Join(keyDir, f.Name())
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			continue
		}
		signers = append(signers, signer)
		logrus.Infof("Loaded %s (%s)", keyPath, signer.PublicKey().Type())
	}

	return ssh.PublicKeys(signers...), nil
}

func (c *Environment) Connect() error {
	endpoint, err := c.SSHEndpoint()
	if err != nil {
		return err
	}
	endpoint = endpoint + ":22"

	auth, err := c.loadSSHKeys()
	if err != nil {
		return err
	}

	conn, err := ssh.Dial("tcp", endpoint,
		&ssh.ClientConfig{
			User: "docker",
			Auth: []ssh.AuthMethod{
				auth,
			},
		},
	)

	if err != nil {
		return err
	}
	c.client = conn
	return nil
}

// Disconnect disconnects the SSH connection to the CloudFormation stack
func (c *Environment) Disconnect() error {
	return c.client.Close()
}

// Run runs the commands over ssh on the CloudFormation stack
func (c *Environment) Run(cmd string) error {
	session, err := c.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	logrus.Infof("$ %s", cmd)

	now := time.Now()
	err = session.Run(cmd)
	duration := time.Since(now)

	if err != nil {
		logrus.Errorf("==> \"%s\" failed after %v: %s", cmd, duration, err)
		return err
	}

	logrus.Infof("==> \"%s\" completed in %v", cmd, duration)
	return nil
}

type Config struct {
	Template string `yaml:"template,omitempty"`

	SSHKeyName string `yaml:"ssh_keyname,omitempty"`

	Managers string `yaml:"managers,omitempty"`
	Workers  string `yaml:"workers,omitempty"`

	InstanceType string `yaml:"instance_type,omitempty"`
}

func Provision(sess *session.Session, name string, config *Config) (*Environment, error) {
	cf := cloudformation.New(sess)

	stack := cloudformation.CreateStackInput{
		StackName: aws.String(name),
		Tags: []*cloudformation.Tag{
			{Key: aws.String("docker"), Value: aws.String("e2e")},
		},
		TemplateURL: aws.String(config.Template),
		Capabilities: []*string{
			aws.String("CAPABILITY_IAM"),
		},
		Parameters: []*cloudformation.Parameter{
			{
				ParameterKey:   aws.String("KeyName"),
				ParameterValue: aws.String(config.SSHKeyName),
			},
			{
				ParameterKey:   aws.String("ClusterSize"),
				ParameterValue: aws.String(config.Workers),
			},
			{
				ParameterKey:   aws.String("ManagerSize"),
				ParameterValue: aws.String(config.Managers),
			},
			{
				ParameterKey:   aws.String("InstanceType"),
				ParameterValue: aws.String(config.InstanceType),
			},
			{
				ParameterKey:   aws.String("ManagerInstanceType"),
				ParameterValue: aws.String(config.InstanceType),
			},
		},
	}

	output, err := cf.CreateStack(&stack)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	logrus.Infof("Stack %s created (%s), waiting to come up...", name, *output.StackId)
	if err := cf.WaitUntilStackCreateComplete(&cloudformation.DescribeStacksInput{
		StackName: output.StackId,
	}); err != nil {
		return nil, err
	}

	logrus.Infof("Stack %s provisioned in %s", name, time.Since(now))
	return New(*output.StackId, sess), nil
}
