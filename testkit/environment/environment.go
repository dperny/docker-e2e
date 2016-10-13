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

// Purge deletes stacks older than `ttl`
func Purge(sess *session.Session, ttl time.Duration) error {
	cf := cloudformation.New(sess)

	input := &cloudformation.ListStacksInput{}
	for {
		resp, err := cf.ListStacks(input)
		if err != nil {
			return err
		}
		for _, ss := range resp.StackSummaries {
			// Skip stacks that don't belong to us.
			// TODO(aluzzardi): Rather than checking the name we should check tags.
			if !strings.HasPrefix(*ss.StackName, "docker-e2e-") {
				continue
			}

			// No point in deleting already deleted stacks.
			if *ss.StackStatus == "DELETE_COMPLETE" || *ss.StackStatus == "DELETE_IN_PROGRESS" {
				continue
			}

			// Skip stacks that haven't yet expired (recently created)
			creation := *ss.CreationTime
			expiration := creation.Add(ttl)
			if expiration.After(time.Now().UTC()) {
				logrus.Warnf("Skipping %s (created %v ago)", *ss.StackName, time.Now().UTC().Sub(creation))
				continue
			}

			logrus.Infof("Cleaning up %s (created %v ago)", *ss.StackName, time.Now().UTC().Sub(creation))
			_, err = cf.DeleteStack(&cloudformation.DeleteStackInput{
				StackName: ss.StackId,
			})
			if err != nil {
				logrus.Errorf("Failed to delete %s: %v", *ss.StackName, err)
			}
		}

		if resp.NextToken == nil {
			return nil
		}

		input.NextToken = resp.NextToken
	}
}

type Environment struct {
	id     string
	cf     *cloudformation.CloudFormation
	client *ssh.Client
}

func New(id string, sess *session.Session) *Environment {
	return &Environment{
		id: id,
		cf: cloudformation.New(sess),
	}
}

func (c *Environment) Destroy() error {
	_, err := c.cf.DeleteStack(&cloudformation.DeleteStackInput{
		StackName: aws.String(c.id),
	})
	return err
}

func (c *Environment) sshEndpoint() (string, error) {
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

func (c *Environment) Connect() error {
	endpoint, err := c.sshEndpoint()
	if err != nil {
		return err
	}

	usr, err := user.Current()
	if err != nil {
		return err
	}

	key, err := ioutil.ReadFile(filepath.Join(usr.HomeDir, "/.ssh/swarm.pem"))
	if err != nil {
		return errors.Wrap(err, "unable to read private key")
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return errors.Wrap(err, "unable to parse private key")
	}

	conn, err := ssh.Dial("tcp", endpoint,
		&ssh.ClientConfig{
			User: "docker",
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
		},
	)
	if err != nil {
		return err
	}
	c.client = conn
	return nil
}

func (c *Environment) Disconnect() error {
	return c.client.Close()
}

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
