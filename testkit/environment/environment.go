package environment

import (
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/pkg/errors"
)

func List(sess *session.Session) ([]*cloudformation.Stack, error) {
	cf := cloudformation.New(sess)

	stacks := make([]*cloudformation.Stack, 0)

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
	id     string
	cf     *cloudformation.CloudFormation
	client *ssh.Client
}

// New returns a new environment
func New(id string, sess *session.Session) *Environment {
	return &Environment{
		id: id,
		cf: cloudformation.New(sess),
	}
}

// Destroy deletes the CloudFormation stack associated with the environment
func (c *Environment) Destroy() error {
	_, err := c.cf.DeleteStack(&cloudformation.DeleteStackInput{
		StackName: aws.String(c.id),
	})
	return err
}

// SSHEndpoint returns the ssh endpoint of the CloudFormation stack
func (c *Environment) SSHEndpoint() (string, error) {
	output, err := c.cf.DescribeStacks(&cloudformation.DescribeStacksInput{
		StackName: aws.String(c.id),
	})
	if err != nil {
		return "", err
	}
	if len(output.Stacks) != 1 {
		return "", errors.New("stack not found")
	}

	for _, o := range output.Stacks[0].Outputs {
		if *o.OutputKey == "SSH" {
			// Formatted as "ssh docker@docker-e2e-20160928-ELB-SSH-1653593963.us-east-1.elb.amazonaws.com"
			endpoint := *o.OutputValue
			return strings.SplitN(endpoint, "@", 2)[1] + ":22", nil
		}
	}

	return "", errors.New("unable to retrieve SSH endpoint")
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
	endpoint, err := c.sshEndpoint()
	if err != nil {
		return err
	}

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

	logrus.Infof("Stack %s created (%s), waiting to come up...", name, *output.StackId)
	if err := cf.WaitUntilStackCreateComplete(&cloudformation.DescribeStacksInput{
		StackName: output.StackId,
	}); err != nil {
		return nil, err
	}

	return New(*output.StackId, sess), nil
}
