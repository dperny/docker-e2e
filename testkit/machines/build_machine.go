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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/client"
)

// TODO - this should be renamed "docker-machine" something or other...

type BuildMachine struct {
	name       string
	dockerHost string
	certPath   string
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
func NewBuildMachines(linuxCount, windowsCount int, dockerRootDir string) ([]Machine, []Machine, error) {
	if windowsCount > 0 {
		return nil, nil, fmt.Errorf("The docker-machine based back-end does not support windows machines")
	}

	id, _ := rand.Int(rand.Reader, big.NewInt(0xffffff))
	linuxMachines := []Machine{}
	var linuxWG sync.WaitGroup
	fail := false
	linuxRes := make(chan Machine)
	for i := 0; i < linuxCount; i++ {
		linuxWG.Add(1)
		go func(index int) {
			defer linuxWG.Done()
			// Some cloud providers can be a little flaky, so try a few times before we give up
			verbose := false
			for r := 0; r < RetryCount; r++ {
				m, err := buildMachineOnce(fmt.Sprintf("%s-%X-%d", NamePrefix, id, index), dockerRootDir, verbose)
				if err == nil {
					linuxRes <- m
					return
				}
				log.Infof("Failed to create machine, retrying: %s", err)
				verbose = true // Crank up logging if something went wrong
				// TODO - Might want to try to explicitly remove here if subsequent attempts fail with conflicts...
			}
			fail = true
			log.Errorf("Failed to create machine after %d tries", RetryCount)
		}(i)
	}

	go func() {
		linuxWG.Wait()
		close(linuxRes)
	}()
	for m := range linuxRes {
		linuxMachines = append(linuxMachines, m)
	}
	if fail {
		for _, m := range linuxMachines {
			if m != nil {
				m.Remove()
			}
		}
		return nil, nil, fmt.Errorf("Failed to create one or more machines")
	}
	return linuxMachines, nil, nil
}

func DockerMachineListEnvironments() ([]*Environment, error) {
	cmd := exec.Command("docker-machine", "ls", "-q")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return nil, err
	}
	envs := []*Environment{}
	// Pattern match the machines to filer out noise, and group them
	re := regexp.MustCompile(fmt.Sprintf(`(%s-[0-9A-F]+)-([0-9]+)`, NamePrefix))
	for _, line := range strings.Split(string(out), "\n") {
		match := re.FindStringSubmatch(line)
		if match != nil {
			envName := match[1]
			m := &BuildMachine{name: match[0]}
			err := m.gatherMachineDetails()
			if err != nil {
				return nil, err
			}
			found := false
			for _, env := range envs {
				if env.StackName == envName {
					found = true
					env.Machines = append(env.Machines, m)
				}
			}
			if !found {
				envs = append(envs, &Environment{envName, []Machine{m}})
			}
		}
	}
	return envs, nil
}

func DockerMachineDestroyEnvironment(name string) error {
	cmd := exec.Command("docker-machine", "ls", "-q")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}
	re := regexp.MustCompile(fmt.Sprintf(`%s-[0-9]+`, name))
	for _, line := range strings.Split(string(out), "\n") {
		match := re.FindStringSubmatch(line)
		if match != nil {
			cmd = exec.Command("docker-machine", "rm", "-f", line)
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.Error(string(out))
				// TODO Should we try force?
				return err
			}
			log.Infof("Machine %s deleted", line)
		}
	}
	return nil
}

func buildMachineOnce(name string, dockerRootDir string, verbose bool) (Machine, error) {
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

	m := &BuildMachine{
		name: name,
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
	err = m.gatherMachineDetails()
	if err != nil {
		// If something went wrong, make sure to clean up after ourselves
		_ = m.Remove()
		return nil, err
	}
	fixupCommand := os.Getenv("MACHINE_FIXUP_COMMAND")
	if fixupCommand != "" {
		log.Infof("Fixing test VM by running: %s %s", m.name, fixupCommand)

		// Can't use `docker-machine ssh` because it doesn't allocate a tty
		// which is needed for sudo.
		cmd = exec.Command("ssh", "-tt", "-l", m.sshUser, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-i", m.sshKeyPath, m.ip, fixupCommand)
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Error(err)
			log.Error(string(out))
			// If something went wrong, make sure to clean up after ourselves
			_ = m.Remove()
			return nil, err
		}
	}
	log.Infof("%s internal IP: %s", m.name, m.internalip)

	log.Infof("Host: %s", m.dockerHost)
	return m, nil
}

func (m *BuildMachine) gatherMachineDetails() error {
	cmd := exec.Command("docker-machine", "inspect", m.name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(err)
		log.Error(string(out))
		return err
	}
	machineInfo := DockerMachineInspect{}
	if err := json.Unmarshal([]byte(out), &machineInfo); err != nil {
		log.Error(err)
		return err
	}
	m.sshUser = machineInfo.Driver.SSHUser
	m.sshKeyPath = machineInfo.Driver.SSHKeyPath

	// Now get the env settings for this new VM
	cmd = exec.Command("docker-machine", "env", m.name)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Error(err)
		log.Error(string(out))
		return err
	} else {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "export DOCKER_HOST=") {
				vals := strings.Split(line, "=")
				m.dockerHost = strings.Trim(vals[1], `"`)
			} else if strings.Contains(line, "export DOCKER_CERT_PATH=") {
				vals := strings.Split(line, "=")
				certDir := strings.Trim(vals[1], `"`)
				m.certPath = certDir
				log.Debugf("Loading certs from %s", certDir)
				cert, err := tls.LoadX509KeyPair(
					fmt.Sprintf("%s/cert.pem", certDir),
					fmt.Sprintf("%s/key.pem", certDir))
				if err != nil {
					return err
				}
				caCert, err := ioutil.ReadFile(
					fmt.Sprintf("%s/ca.pem", certDir))
				if err != nil {
					return err
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
		return err
	}
	m.ip = strings.TrimSpace(string(out))
	log.Debugf("%s external IP: %s", m.name, m.ip)

	if os.Getenv("MACHINE_DRIVER") == "virtualbox" {
		log.Info("Detected virtualbox - working around broken internal IP address limitations.")
		m.internalip = m.ip
	} else {
		cmd = exec.Command("docker-machine", "ssh", m.name, "ip route get 8.8.8.8| cut -d' ' -f8|head -1")
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Error(string(out))
			return err
		}
		m.internalip = strings.TrimSpace(string(out))
	}
	if m.sshKeyPath == "" {
		m.sshKeyPath = filepath.Join(m.certPath, "id_rsa")
	}
	return nil
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
	return CatHostFile(m, hostPath)
}

// Get the content of a directory as a tar file from the engine
func (m *BuildMachine) TarHostDir(hostPath string) ([]byte, error) {
	return TarHostDir(m, hostPath)
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

func (m *BuildMachine) IsWindows() bool {
	return false
}

func (m *BuildMachine) GetConnectionEnv() string {
	return strings.Join([]string{
		fmt.Sprintf(`export DOCKER_HOST="tcp://%s:2376"`, m.ip),
		fmt.Sprintf(`export DOCKER_CERT_PATH="%s"`, m.certPath),
		"export DOCKER_TLS_VERIFY=1",
		fmt.Sprintf("# %s", m.name),
		fmt.Sprintf("# ssh -i %s %s@%s", m.sshKeyPath, m.sshUser, m.ip),
	}, "\n")
}
