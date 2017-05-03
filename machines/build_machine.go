package machines

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/client"
)

// TODO - this should be renamed "docker-machine" something or other...

type BuildMachine struct {
	name       string
	dockerHost string
	tlsConfig  *tls.Config
	sshKeyPath string
	sshUser    string
	ip         string // Cache so we don't have to look it up so much
	internalip string // Cache so we don't have to look it up so much
}

type DockerMachineInspectDriver struct {
	IPAddress  string
	SSHUser    string
	SSHKeyPath string
}

type DockerMachineInspect struct {
	Driver DockerMachineInspectDriver
}

// Generate a new machine using docker-machine CLI
func NewBuildMachine(dockerRootDir string) (Machine, error) {
	// Some cloud providers can be a little flaky, so try a few times before we give up
	verbose := false
	for i := 0; i < RetryCount; i++ {
		machine, err := buildMachineOnce(dockerRootDir, verbose)
		if err == nil {
			return machine, err
		}
		log.Infof("Failed to create machine, retrying: %s", err)
		verbose = true // Crank up logging if something went wrong
		// TODO - Might want to try to explicitly remove here if subsequent attempts fail with conflicts...
	}
	return nil, fmt.Errorf("Failed to create machine after %d tries", RetryCount)
}

func buildMachineOnce(dockerRootDir string, verbose bool) (Machine, error) {
	machineDriver := os.Getenv("MACHINE_DRIVER")
	if machineDriver == "" {
		return nil, fmt.Errorf(`You forgot to "export MACHINE_DRIVER=virtualbox" (or your favorite driver)`)
	}

	_, err := exec.LookPath("docker-machine")
	if err != nil {
		return nil, fmt.Errorf("You must have docker-machine installed locally in your path!")
	}

	args := []string{
		"create",
		"--driver",
		machineDriver,
	}

	if verbose {
		args = append([]string{"-D"}, args...)
	}

	createFlags := os.Getenv("MACHINE_CREATE_FLAGS")
	if createFlags != "" {
		args = append(args, strings.Split(createFlags, " ")...)
	}
	if dockerRootDir != "" {
		args = append(args, "--engine-opt", fmt.Sprintf("graph=%s", dockerRootDir))
	}

	id, _ := rand.Int(rand.Reader, big.NewInt(0xffffff))
	m := &BuildMachine{
		name: fmt.Sprintf("%s-%X", NamePrefix, id),
	}

	args = append(args, m.name)

	log.Infof("Creating new test VM: %s", m.name)
	cmd := exec.Command("docker-machine", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(err)
		log.Error(string(out))
		// If something went wrong, make sure to clean up after ourselves
		_ = m.Remove()
		return nil, err
	}
	log.Infof("Created new test VM: %s", m.name)

	cmd = exec.Command("docker-machine", "inspect", m.name)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Error(err)
		log.Error(string(out))
		_ = m.Remove()
		return nil, err
	}
	machineInfo := DockerMachineInspect{}
	if err := json.Unmarshal([]byte(out), &machineInfo); err != nil {
		log.Error(err)
		_ = m.Remove()
		return nil, err
	}

	fixupCommand := os.Getenv("MACHINE_FIXUP_COMMAND")
	if fixupCommand != "" {
		log.Infof("Fixing test VM by running: %s %s", m.name, fixupCommand)

		// Can't use `docker-machine ssh` because it doesn't allocate a tty
		// which is needed for sudo.
		cmd = exec.Command("ssh", "-tt", "-l", machineInfo.Driver.SSHUser, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-i", machineInfo.Driver.SSHKeyPath, machineInfo.Driver.IPAddress, fixupCommand)
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Error(err)
			log.Error(string(out))
			// If something went wrong, make sure to clean up after ourselves
			_ = m.Remove()
			return nil, err
		}
	}

	// Now get the env settings for this new VM
	cmd = exec.Command("docker-machine", "env", m.name)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Error(err)
		log.Error(string(out))
		// If something went wrong, make sure to clean up after ourselves
		_ = m.Remove()
		return nil, err
	} else {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "export DOCKER_HOST=") {
				vals := strings.Split(line, "=")
				m.dockerHost = strings.Trim(vals[1], `"`)
			} else if strings.Contains(line, "export DOCKER_CERT_PATH=") {
				vals := strings.Split(line, "=")
				certDir := strings.Trim(vals[1], `"`)
				log.Infof("Loading certs from %s", certDir)
				cert, err := tls.LoadX509KeyPair(
					fmt.Sprintf("%s/cert.pem", certDir),
					fmt.Sprintf("%s/key.pem", certDir))
				if err != nil {
					// If something went wrong, make sure to clean up after ourselves
					_ = m.Remove()
					return nil, err
				}
				caCert, err := ioutil.ReadFile(
					fmt.Sprintf("%s/ca.pem", certDir))
				if err != nil {
					// If something went wrong, make sure to clean up after ourselves
					_ = m.Remove()
					return nil, err
				}
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				m.tlsConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
					RootCAs:      caCertPool,
				}
			}
		}
	}

	// Populate the IP addresses so we can return from the cached data
	cmd = exec.Command("docker-machine", "ip", m.name)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return nil, err
	}
	m.ip = strings.TrimSpace(string(out))
	log.Infof("%s external IP: %s", m.name, m.ip)

	if os.Getenv("MACHINE_DRIVER") == "virtualbox" {
		log.Info("Detected virtualbox - working around broken internal IP address limitations.")
		m.internalip = m.ip
	} else {
		cmd = exec.Command("docker-machine", "ssh", m.name, "ip route get 8.8.8.8| cut -d' ' -f8|head -1")
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Error(string(out))
			return nil, err
		}
		m.internalip = strings.TrimSpace(string(out))
	}
	log.Infof("%s internal IP: %s", m.name, m.internalip)

	log.Infof("Host: %s", m.dockerHost)
	return m, nil
}

func (m *BuildMachine) GetName() string {
	return m.name
}

func (m *BuildMachine) GetDockerHost() string {
	return m.dockerHost
}

func (m *BuildMachine) GetEngineAPI() (*client.Client, error) {
	return m.GetEngineAPIWithTimeout(Timeout)
}

func (m *BuildMachine) GetEngineAPIWithTimeout(timeout time.Duration) (*client.Client, error) {
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

// Remove the machine after the tests have completed
func (m *BuildMachine) Remove() error {
	if os.Getenv("PRESERVE_TEST_MACHINE") != "" {
		log.Infof("Skipping removal of machine %s with PRESERVE_TEST_MACHINE set", m.name)
		return nil
	}
	if m.name == "" {
		log.Info("Machine already deleted")
		return nil
	}
	cmd := exec.Command("docker-machine", "rm", "-f", m.name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		// TODO Should we try force?
		return err
	}
	log.Infof("Machine %s deleted", m.name)
	m.name = ""
	return nil
}

func (m *BuildMachine) Stop() error {
	cmd := exec.Command("docker-machine", "stop", m.name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}
	return nil
}

func (m *BuildMachine) Start() error {
	cmd := exec.Command("docker-machine", "start", m.name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}
	return nil
}

// Return the public IP of the machine
func (m *BuildMachine) GetIP() (string, error) {
	return m.ip, nil
}

// Get the internal IP (useful for join operations)
func (m *BuildMachine) GetInternalIP() (string, error) {
	return m.internalip, nil
}

func (m *BuildMachine) MachineSSH(command string) (string, error) {
	cmd := exec.Command("docker-machine", "ssh", m.name, command)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Get the contents of a specific file on the engine
func (m *BuildMachine) CatHostFile(hostPath string) ([]byte, error) {
	return catHostFile(m, hostPath)
}

// Get the content of a directory as a tar file from the engine
func (m *BuildMachine) TarHostDir(hostPath string) ([]byte, error) {
	return tarHostDir(m, hostPath)
}

// Write data from an io.Reader to a file on the machine with 0600 perms.
func (m *BuildMachine) WriteFile(filePath string, data io.Reader) error {
	f, err := ioutil.TempFile("/tmp", "E2ETestTempFile")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()

	_, err = io.Copy(f, data)
	if err != nil {
		return err
	}

	cmd := exec.Command("docker-machine", "scp",
		fmt.Sprintf("localhost:%s", f.Name()),
		fmt.Sprintf("%s:%s", m.name, filePath))
	out, err := cmd.CombinedOutput()
	log.Info(string(out))
	if err != nil {
		log.Error(string(out))
		return err
	}
	return nil
}
