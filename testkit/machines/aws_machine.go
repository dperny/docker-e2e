package machines

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/cloudflare/cfssl/log"
	"github.com/docker/docker/client"
	"github.com/kr/pty"
)

var (
	AWSDiskDir       = "/tmp/e2e"
	AWSRegion        = "us-east-1"
	AWSSSHUser       = "ubuntu"
	AWSKeyName       = ""
	AWSKeyPath       = ""
	AWSAMI           = "ami-4dd2575b" // Ubuntu 16.04
	AWSInstanceType  = "t2.micro"
	AWSSecurityGroup = "sg-65ebb41a" // Hardcoded to "testkit" in docker-core us-east-1
)

func init() {
	diskDir := os.Getenv("AWS_DISK_DIR")
	if diskDir != "" {
		AWSDiskDir = diskDir
	}
	region := os.Getenv("AWS_REGION")
	if region != "" {
		AWSRegion = region
	}
	user := os.Getenv("AWS_SSH_USER")
	if user != "" {
		AWSSSHUser = user
	}
	keyName := os.Getenv("AWS_KEY_NAME")
	if keyName != "" {
		AWSKeyName = keyName
	}
	keyPath := os.Getenv("AWS_KEY_PATH")
	if keyName != "" {
		AWSKeyPath = keyPath
	}
	ami := os.Getenv("AWS_AMI")
	if ami != "" {
		AWSAMI = ami
	}
	instance := os.Getenv("AWS_INSTANCE_TYPE")
	if instance != "" {
		AWSInstanceType = instance
	}
}

func newSession() *session.Session {
	return session.Must(session.NewSession(aws.NewConfig().WithRegion(AWSRegion)))
}

type AWSMachine struct {
	name       string
	publicIP   string
	privateIP  string
	sshUser    string
	dockerHost string
	tlsConfig  *tls.Config
	isWindows  bool
}

func NewAWSMachines(linuxCount, windowsCount int) ([]Machine, []Machine, error) {
	if AWSKeyName == "" || AWSKeyPath == "" {
		return nil, nil, fmt.Errorf("Tu use the aws driver, you must set AWS_KEY_NAME and AWS_KEY_PATH")
	}

	// TODO(aluzzardi): Move outside
	err := VerifyCA(AWSDiskDir)
	if err != nil {
		return nil, nil, err
	}

	cert, err := tls.LoadX509KeyPair(filepath.Join(AWSDiskDir, "cert.pem"), filepath.Join(AWSDiskDir, "key.pem"))
	if err != nil {
		return nil, nil, err
	}
	caCert, err := ioutil.ReadFile(filepath.Join(AWSDiskDir, "ca.pem"))
	if err != nil {
		return nil, nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	id, _ := rand.Int(rand.Reader, big.NewInt(0xffffff))
	name := fmt.Sprintf("%s-%X", NamePrefix, id)

	sess := newSession()
	svc := ec2.New(sess)

	params := &ec2.RunInstancesInput{
		ImageId:      aws.String(AWSAMI),
		MaxCount:     aws.Int64(int64(linuxCount)),
		MinCount:     aws.Int64(int64(linuxCount)),
		InstanceType: aws.String(AWSInstanceType),
		KeyName:      aws.String(AWSKeyName),
		BlockDeviceMappings: []*ec2.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/sda1"),
				Ebs: &ec2.EbsBlockDevice{
					DeleteOnTermination: aws.Bool(true),
					VolumeSize:          aws.Int64(20),
					VolumeType:          aws.String("gp2"),
				},
			},
		},
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: aws.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(name),
					},
					{
						Key:   aws.String("testkit"),
						Value: aws.String("true"),
					},
				},
			},
		},
		SecurityGroupIds: []*string{
			aws.String(AWSSecurityGroup),
		},
	}

	logrus.Infof("Provisioning %d machines...", linuxCount)
	now := time.Now()
	resp, err := svc.RunInstances(params)

	if err != nil {
		return nil, nil, err
	}

	logrus.Infof("Waiting for instances to come up...")
	instanceIDs := []*string{}
	for _, instance := range resp.Instances {
		instanceIDs = append(instanceIDs, instance.InstanceId)
	}
	svc.WaitUntilInstanceRunning(&ec2.DescribeInstancesInput{
		InstanceIds: instanceIDs,
	})

	duration := time.Since(now)
	logrus.Infof("All %d instances are running (duration: %v)", linuxCount, duration)

	// We have to query them again to gather the public IP address and such.
	reservations, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: instanceIDs,
	})
	if err != nil {
		panic(err)
	}

	machines := []Machine{}
	for _, reservation := range reservations.Reservations {
		for _, instance := range reservation.Instances {
			m := &AWSMachine{
				name:       *instance.InstanceId,
				publicIP:   *instance.PublicIpAddress,
				privateIP:  *instance.PrivateIpAddress,
				sshUser:    AWSSSHUser,
				dockerHost: fmt.Sprintf("tcp://%s:2376", *instance.PublicIpAddress),
				tlsConfig:  tlsConfig,
			}
			machines = append(machines, m)
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(machines))
	for _, machine := range machines {
		wg.Add(1)
		go func() {
			m := machine.(*AWSMachine)
			m.waitReady()
			errCh <- m.provision()
			wg.Done()
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return nil, nil, err
		}
	}
	return machines, []Machine{}, nil
}

func (m *AWSMachine) waitReady() {
	for {
		out, err := m.MachineSSH("uptime")
		if err != nil && strings.Contains(out, "is not recognized as an internal or external command") {
			log.Debug("Detected windows image booted")
			// TODO would be nice to give some basic "uptime" info... but that's kinda kludgy in windows...
			m.isWindows = true
			return
		} else if err != nil {
			//log.Debugf("XXX Failed to ssh to %s: %s: %s", m.GetName(), err, out)
			time.Sleep(500 * time.Millisecond)
		} else if strings.TrimSpace(out) == "" {
			log.Debugf("Got empty output from the other side... trying again...")
			time.Sleep(500 * time.Millisecond)
		} else {
			log.Debugf("%s has been up %s", m.GetName(), out)
			return
		}
	}
}

func (m *AWSMachine) provision() error {
	now := time.Now()
	defer func() {
		logrus.Infof("Provisioning %s completed in %v", m.name, time.Since(now))
	}()

	out, err := m.MachineSSH(
		fmt.Sprintf(`sudo hostname "%s"; sudo sed -e 's/.*/%s/' -i /etc/hostname; sudo sed -e 's/127\.0\.1\.1.*/127.0.1.1 %s/' -i /etc/hosts`,
			m.GetName(), m.GetName(), m.GetName()))
	if err != nil {
		logrus.Warnf("Failed to set hostname to %s: %s: %s", m.GetName(), err, out)
	}
	return VerifyDockerEngine(m, AWSDiskDir)
}

func (m *AWSMachine) GetName() string {
	return m.name
}

func (m *AWSMachine) GetDockerHost() string {
	return m.dockerHost
}

// GetEngineAPIWithTimeout gets an engine API client with a default timeout
func (m *AWSMachine) GetEngineAPI() (*client.Client, error) {
	return m.GetEngineAPIWithTimeout(Timeout)
}

// GetEngineAPIWithTimeout gets an engine API client with a timeout set
func (m *AWSMachine) GetEngineAPIWithTimeout(timeout time.Duration) (*client.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: m.tlsConfig,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	version := "" // TODO
	return client.NewClient(m.dockerHost, version, httpClient, nil)
}

func (m *AWSMachine) Remove() error {
	return errors.New("not implemented")
}

func (m *AWSMachine) Stop() error {
	return errors.New("not implemented")
}

func (m *AWSMachine) Start() error {
	return errors.New("not implemented")
}

func (m *AWSMachine) GetIP() (string, error) {
	return m.publicIP, nil
}

func (m *AWSMachine) GetInternalIP() (string, error) {
	return m.privateIP, nil
}

func (m *AWSMachine) CatHostFile(hostPath string) ([]byte, error) {
	return CatHostFile(m, hostPath)
}

func (m *AWSMachine) TarHostDir(hostPath string) ([]byte, error) {
	return TarHostDir(m, hostPath)
}

// MachineSSH runs an ssh command and returns a string of the combined stdout/stderr output once done
func (m *AWSMachine) MachineSSH(command string) (string, error) {
	buf := bytes.Buffer{}
	args := []string{
		"ssh", "-q",
		"-o", "StrictHostKeyChecking=no",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "ConnectTimeout=8",
		"-o", "VerifyHostKeyDNS=no",
		"-i", AWSKeyPath,
	}
	args = append(args, m.sshUser+"@"+m.publicIP, command)
	logrus.Debugf("SSH to %s: %v", m.name, args)
	cmd := exec.Command(args[0], args[1:]...)
	tty, err := pty.Start(cmd)
	if err != nil {
		logrus.Debugf("Failed to establish tty for ssh command: %s", err)
		return "", err
	}
	defer tty.Close()

	go func() {
		scanner := bufio.NewScanner(tty)
		for scanner.Scan() {
			buf.WriteString(scanner.Text())
		}
	}()

	// TODO - do we need to inject any stdin?
	/*
		go func() {
			io.Copy(tty, os.Stdin)
		}()
	*/

	err = cmd.Wait()
	return strings.TrimSpace(buf.String()), err
}

// Write data from an io.Reader to a file on the machine with 0600 perms.
func (m *AWSMachine) WriteFile(filePath string, data io.Reader) error {
	f, err := ioutil.TempFile("/tmp", "orcaTestTempFile")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()

	_, err = io.Copy(f, data)
	if err != nil {
		return err
	}
	return m.writeLocalFile(f.Name(), filePath)
}

func (m *AWSMachine) writeLocalFile(localFilePath, remoteFilePath string) error {
	cmd := exec.Command("scp", "-i", AWSKeyPath, "-q",
		"-o", "StrictHostKeyChecking=no",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "VerifyHostKeyDNS=no",
		localFilePath,
		fmt.Sprintf("%s@%s:%s", m.sshUser, m.publicIP, remoteFilePath))
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if out != "" {
		logrus.Debug(out)
	}
	if err != nil {
		logrus.Error(string(out))
		return err
	}
	return nil
}

func (m *AWSMachine) GetConnectionEnv() string {
	lines := []string{
		fmt.Sprintf(`export DOCKER_HOST="%s"`, m.dockerHost),
		fmt.Sprintf(`export DOCKER_CERT_PATH="%s"`, AWSDiskDir),
		"export DOCKER_TLS_VERIFY=1",
		fmt.Sprintf("# %s", m.name),
	}
	lines = append(lines, fmt.Sprintf("# ssh -i %s %s@%s", AWSKeyPath, m.sshUser, m.publicIP))
	return strings.Join(lines, "\n")
}

func (m *AWSMachine) IsWindows() bool {
	return m.isWindows
}
