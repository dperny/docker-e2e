package machines

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/client"
	"github.com/kr/pty"
)

var (
	VirshDiskDir   = "/e2e"
	VirshOSLinux   = "ubuntu16.04"
	VirshOSWindows = "winnanors1"
)

const (
	domainXMLTemplate = `<domain type='kvm'>
  <name>{{.MachineName}}</name> <memory unit='M'>{{.Memory}}</memory>
  <vcpu>{{.CPUCount}}</vcpu>
  <features><acpi/><apic/><pae/></features>
  <cpu mode='host-passthrough'></cpu>
  <os>
    <type>hvm</type>
    <boot dev='hd'/>
    <bootmenu enable='no'/>
  </os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='unsafe' io='threads' />
      <source file='{{.DiskPath}}'/>
      <target dev='vda' bus='{{.DiskType}}'/>
    </disk>
    <graphics type='vnc' autoport='yes' listen='127.0.0.1'>
      <listen type='address' address='127.0.0.1'/>
    </graphics>
    <interface type='network'>
      <source network='default'/>
      <model type='{{.NICType}}'/>
    </interface>
  </devices>
</domain>`
)

type VirshMachine struct {
	MachineName string
	dockerHost  string
	tlsConfig   *tls.Config
	sshKeyPath  string
	sshUser     string
	ip          string // Cache so we don't have to look it up so much
	internalip  string // Cache so we don't have to look it up so much
	BaseDisk    string
	DiskPath    string
	CPUCount    int
	Memory      int
	isWindows   bool
	DiskType    string
	NICType     string
}

func init() {
	diskDir := os.Getenv("VIRSH_DISK_DIR")
	if diskDir != "" {
		VirshDiskDir = diskDir
	}
	baseOSLinux := os.Getenv("VIRSH_OS_LINUX")
	if baseOSLinux != "" {
		VirshOSLinux = baseOSLinux
	}
	baseOSWindows := os.Getenv("VIRSH_OS_WINDOWS")
	if baseOSWindows != "" {
		VirshOSWindows = baseOSWindows
	}
}

func getActiveMachines() []string {
	cmd := exec.Command("virsh", "-q", "list")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Info("Failed to get list - assuming no VMs: %s", err)
	}
	nameRegex := regexp.MustCompile(`\s+(\S+)\s+running`)
	machines := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		matches := nameRegex.FindStringSubmatch(line)
		if len(matches) > 0 {
			machines = append(machines, matches[1])
		}
	}
	return machines
}

// Generate a new machine using docker-machine CLI
func NewVirshMachines(linuxCount, windowsCount int) ([]Machine, []Machine, error) {
	if VirshDiskDir == "" {
		return nil, nil, fmt.Errorf("To use the vrish driver, you must set VIRSH_DISK_DIR to point to where your base OS disks and ssh key live")
	}
	err := VerifyCA(VirshDiskDir)
	if err != nil {
		return nil, nil, err
	}

	baseOSLinux := filepath.Join(VirshDiskDir, VirshOSLinux+".qcow2")
	baseOSWindows := filepath.Join(VirshDiskDir, VirshOSWindows+".qcow2")

	if linuxCount > 0 {
		if _, err := os.Stat(baseOSLinux); err != nil {
			return nil, nil, fmt.Errorf("Unable to locate %s: %s", baseOSLinux, err)
		}
	}
	if windowsCount > 0 {
		if _, err := os.Stat(baseOSWindows); err != nil {
			return nil, nil, fmt.Errorf("Unable to locate %s: %s", baseOSWindows, err)
		}
	}

	// Check for existence of an ssh key, and skip if not found
	sshKeyPath := filepath.Join(VirshDiskDir, "id_rsa")
	if _, err := os.Stat(sshKeyPath); err != nil {
		log.Debugf("No ssh key found, assuming password-less login. (%s)", sshKeyPath)
		sshKeyPath = ""
	}

	timer := time.NewTimer(5 * time.Minute) // TODO - make configurable
	errChan := make(chan error)
	resChan := make(chan []*VirshMachine)

	go func() {
		log.Infof("Creating %d linux VMs based on %s", linuxCount, VirshOSLinux)
		id, _ := rand.Int(rand.Reader, big.NewInt(0xffffff))
		linuxMachines := []*VirshMachine{}
		windowsMachines := []*VirshMachine{}
		index := 0
		for ; index < linuxCount; index++ {
			m := &VirshMachine{
				MachineName: fmt.Sprintf("%s-%X-%d", NamePrefix, id, index),
				BaseDisk:    baseOSLinux,
				CPUCount:    1,        // TODO - make configurable
				Memory:      2048,     // TODO - make configurable
				sshUser:     "docker", // TODO - make configurable
				sshKeyPath:  sshKeyPath,
				DiskType:    "virtio",
				NICType:     "virtio",
			}
			if err := m.cloneDisk(); err != nil {
				errChan <- err
				return
			}
			if err := m.define(); err != nil {
				errChan <- err
				return
			}
			if err := m.Start(); err != nil {
				errChan <- err
				return
			}
			cert, err := tls.LoadX509KeyPair(filepath.Join(VirshDiskDir, "cert.pem"), filepath.Join(VirshDiskDir, "key.pem"))
			if err != nil {
				errChan <- err
				return
			}
			caCert, err := ioutil.ReadFile(filepath.Join(VirshDiskDir, "ca.pem"))
			if err != nil {
				errChan <- err
				return
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			m.tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
			}
			linuxMachines = append(linuxMachines, m)
		}
		log.Infof("Creating %d windows VMs based on %s", windowsCount, VirshOSWindows)
		for ; index-linuxCount < windowsCount; index++ {
			m := &VirshMachine{
				MachineName: fmt.Sprintf("%s-%X-%d", NamePrefix, id, index),
				BaseDisk:    baseOSWindows,
				CPUCount:    1,        // TODO - make configurable
				Memory:      2048,     // TODO - make configurable
				sshUser:     "docker", // TODO - make configurable
				sshKeyPath:  sshKeyPath,
				DiskType:    "ide",
				NICType:     "e1000",
			}
			if err := m.cloneDisk(); err != nil {
				errChan <- err
				return
			}
			if err := m.define(); err != nil {
				errChan <- err
				return
			}
			if err := m.Start(); err != nil {
				errChan <- err
				return
			}
			cert, err := tls.LoadX509KeyPair(filepath.Join(VirshDiskDir, "cert.pem"), filepath.Join(VirshDiskDir, "key.pem"))
			if err != nil {
				errChan <- err
				return
			}
			caCert, err := ioutil.ReadFile(filepath.Join(VirshDiskDir, "ca.pem"))
			if err != nil {
				errChan <- err
				return
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			m.tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
			}
			windowsMachines = append(windowsMachines, m)
		}

		var wg sync.WaitGroup

		res := []*VirshMachine{}
		machineErrChan := make(chan error, linuxCount+windowsCount)
		for _, m := range linuxMachines {
			wg.Add(1)
			go func(m *VirshMachine) {
				var result error
				// Set the hostname
				out, err := m.MachineSSH(
					fmt.Sprintf(`sudo hostname "%s"; sudo sed -e 's/.*/%s/' -i /etc/hostname; sudo sed -e 's/127\.0\.1\.1.*/127.0.1.1 %s/' -i /etc/hosts`,
						m.GetName(), m.GetName(), m.GetName()))
				if err != nil {
					log.Warnf("Failed to set hostname to %s: %s: %s", m.GetName(), err, out)
				}
				result = VerifyDockerEngine(m, VirshDiskDir)

				machineErrChan <- result
				wg.Done()
			}(m)
			res = append(res, m)
		}
		for _, m := range windowsMachines {
			wg.Add(1)
			go func(m *VirshMachine) {
				var result error
				out, err := m.MachineSSH(
					fmt.Sprintf(`powershell rename-computer -newname "%s" -restart`, m.GetName()))
				if err != nil {
					log.Warnf("Failed to set hostname to %s: %s: %s", m.GetName(), err, out)
				}
				// Give it a few seconds to reboot before we start hammering on it...
				time.Sleep(5 * time.Second) // TODO - need a better way to tell if we've finished the reboot
				result = VerifyDockerEngineWindows(m, VirshDiskDir)
				machineErrChan <- result
				wg.Done()
			}(m)
			res = append(res, m)
		}
		wg.Wait()
		close(machineErrChan)
		for err := range machineErrChan {
			if err != nil {
				log.Debugf("XXX sleeping for 10s to allow you to suspend and poke around")
				time.Sleep(10 * time.Second)
				// Detected errors, destroy all the machines we created
				for _, m := range append(linuxMachines, windowsMachines...) {
					m.Remove()
				}
				errChan <- err
				return
			}
		}
		resChan <- res
		return
	}()
	select {
	case res := <-resChan:
		linuxMachines := []Machine{}
		windowsMachines := []Machine{}
		for _, m := range res {
			if m.IsWindows() {
				windowsMachines = append(windowsMachines, m)
			} else {
				linuxMachines = append(linuxMachines, m)
			}
		}
		return linuxMachines, windowsMachines, nil
	case err := <-errChan:
		return nil, nil, err
	case <-timer.C:
		return nil, nil, fmt.Errorf("Unable to create %d machines within timeout", linuxCount)
	}
}

func VirshListEnvironments() ([]*Environment, error) {
	envs := []*Environment{}
	// Pattern match the machines to filer out noise, and group them
	re := regexp.MustCompile(fmt.Sprintf(`(%s-[0-9A-F]+)-([0-9]+)`, NamePrefix))
	for _, line := range getActiveMachines() {
		match := re.FindStringSubmatch(line)
		if match != nil {
			envName := match[1]
			m := &VirshMachine{MachineName: match[0]}
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

func (m *VirshMachine) gatherMachineDetails() error {
	m.GetIP()
	// TODO - consider taking the plunge and parsing all the gory XML...
	cmd := exec.Command("virsh", "vcpucount", m.MachineName, "--current")
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		log.Warnf("Failed to gather CPU count %s: %s: %s", m.MachineName, err, out)
	} else {
		m.CPUCount, err = strconv.Atoi(out)
	}

	cmd = exec.Command("virsh", "domblklist", m.MachineName)
	data, err = cmd.CombinedOutput()
	if err != nil {
		log.Warnf("Failed to gather disk info %s: %s: %s", m.MachineName, err, out)
	} else {
		// Bleck!
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		re := regexp.MustCompile(`\S+\s+(\S+)`)
		if len(lines) > 2 {
			match := re.FindStringSubmatch(lines[2]) // Skip the two lines of header
			if match != nil {
				// Assume the ssh key is right next to the disk
				m.sshKeyPath = filepath.Join(path.Dir(match[1]), "id_rsa")
			}

		}
	}
	m.sshUser = "docker"
	return nil
}

func VirshDestroyEnvironment(name string) error {
	re := regexp.MustCompile(fmt.Sprintf(`%s-[0-9]+`, name))
	for _, line := range getActiveMachines() {
		match := re.FindStringSubmatch(line)
		if match != nil {
			diskPath := filepath.Join(VirshDiskDir, line+".qcow2") // XXX Potentially fragile
			cmd := exec.Command("virsh", "destroy", line)
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.Warn(string(out))
			}
			cmd = exec.Command("virsh", "undefine", "--storage", diskPath, line)
			out, err = cmd.CombinedOutput()
			if err != nil {
				log.Error(string(out))
				return err
			}

			// If the disk still exists, nuke it, but ignore errors
			os.Remove(diskPath)

			log.Infof("Machine %s deleted", line)
		}
	}
	return nil
}

func (m *VirshMachine) cloneDisk() error {
	dir := path.Dir(m.BaseDisk)
	linkedCloneName := filepath.Join(dir, m.MachineName+".qcow2")
	if _, err := os.Stat(linkedCloneName); err == nil {
		return fmt.Errorf("Linked clone %s of base disk %s already exists!", linkedCloneName, m.BaseDisk)
	}
	log.Debugf("Creating linked clone %s with base disk %s", linkedCloneName, m.BaseDisk)
	cmd := exec.Command("qemu-img", "create", "-f", "qcow2", "-o", "backing_fmt=qcow2", "-b", m.BaseDisk, linkedCloneName)
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to create linked clone %s on %s: %s: %s", linkedCloneName, m.BaseDisk, out, err)
	}
	log.Debug(out)
	m.DiskPath = linkedCloneName
	return nil
}

func (m *VirshMachine) define() error {
	log.Debugf("Creating vm %s", m.MachineName)
	tmpl, err := template.New("domain").Parse(domainXMLTemplate)
	if err != nil {
		return err
	}
	var xml bytes.Buffer
	err = tmpl.Execute(&xml, m)
	if err != nil {
		return err
	}

	// Write it out to a temporary file
	defFile := filepath.Join(path.Dir(m.DiskPath), m.MachineName+".xml")
	err = ioutil.WriteFile(defFile, xml.Bytes(), 0644)
	if err != nil {
		return err
	}
	defer os.Remove(defFile)

	cmd := exec.Command("virsh", "define", defFile)
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to create %s: %s: %s", m.MachineName, err, out)
	}
	return nil
}

// GetName retrieves the machines name
func (m *VirshMachine) GetName() string {
	return m.MachineName
}

// GetDockerHost reports the machines docker host
func (m *VirshMachine) GetDockerHost() string {
	return m.dockerHost
}

// GetEngineAPIWithTimeout gets an engine API client with a default timeout
func (m *VirshMachine) GetEngineAPI() (*client.Client, error) {
	return m.GetEngineAPIWithTimeout(Timeout)
}

// GetEngineAPIWithTimeout gets an engine API client with a timeout set
func (m *VirshMachine) GetEngineAPIWithTimeout(timeout time.Duration) (*client.Client, error) {
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

// IsRunning returns true if this machine is currently running
func (m *VirshMachine) IsRunning() bool {
	names := getActiveMachines()

	for _, name := range names {
		if m.MachineName == name {
			return true
		}

	}
	return false
}

// Remove the machiine after the tests have completed
func (m *VirshMachine) Remove() error {
	if os.Getenv("PRESERVE_TEST_MACHINE") != "" {
		log.Infof("Skipping removal of machine %s with PRESERVE_TEST_MACHINE set", m.GetName())
		return nil
	}
	if m.IsRunning() {
		m.Kill()
	}

	cmd := exec.Command("virsh", "undefine", "--storage", m.DiskPath, m.MachineName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}

	// If the disk still exists, nuke it, but ignore errors
	os.Remove(m.DiskPath)

	log.Infof("Machine %s deleted", m.MachineName)
	m.MachineName = ""
	return nil
}

// Remove the machiine after the tests have completed
func (m *VirshMachine) RemoveAndPreserveDisk() error {
	if os.Getenv("PRESERVE_TEST_MACHINE") != "" {
		log.Infof("Skipping removal of machine %s with PRESERVE_TEST_MACHINE set", m.GetName())
		return nil
	}
	if m.IsRunning() {
		m.Stop()
	}

	cmd := exec.Command("virsh", "undefine", m.MachineName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}

	log.Infof("Preserving %s", m.DiskPath)

	log.Infof("Machine %s deleted", m.MachineName)
	m.MachineName = ""
	return nil
}

// Stop gracefully shuts down the machine
func (m *VirshMachine) Stop() error {
	cmd := exec.Command("virsh", "shutdown", m.MachineName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}
	return nil
}

// Kill forcefully stops the virtual machine (likely to corrupt the machine, so
// do not use this if you intend to start the machine again)
func (m *VirshMachine) Kill() error {
	cmd := exec.Command("virsh", "destroy", m.MachineName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}

	// Make sure it's stopped before returning...
	resChan := make(chan error)

	go func(m *VirshMachine) {
		for {
			if !m.IsRunning() {
				resChan <- nil
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}(m)

	timer := time.NewTimer(1 * time.Minute) // TODO - make configurable
	select {
	case res := <-resChan:
		log.Debugf("Got %v on resChan", res)
		return res
	case <-timer.C:
		return fmt.Errorf("Unable to kill docker engine on %s within timeout", m.MachineName)
	}
}

// Start powers on the VM
func (m *VirshMachine) Start() error {
	cmd := exec.Command("virsh", "start", m.MachineName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}
	resChan := make(chan error)
	// wait for it to power on (by checking virsh -q domifaddr m.GetName())
	go func(m *VirshMachine) {
		log.Debugf("Waiting for IP to appear for %s", m.GetName())
		m.GetIP()
		log.Debugf("Machine %s has IP %s", m.GetName(), m.ip)

		// Loop until we can ssh in
		for {
			out, err := m.MachineSSH("uptime")
			if err != nil && strings.Contains(out, "is not recognized as an internal or external command") {
				log.Debug("Detected windows image booted")
				// TODO would be nice to give some basic "uptime" info... but that's kinda kludgy in windows...
				m.isWindows = true
				break
			} else if err != nil {
				//log.Debugf("XXX Failed to ssh to %s: %s: %s", m.GetName(), err, out)
				time.Sleep(500 * time.Millisecond)
			} else if strings.TrimSpace(out) == "" {
				log.Debugf("Got empty output from the other side... trying again...")
				time.Sleep(500 * time.Millisecond)
			} else {
				log.Debugf("%s has been up %s", m.GetName(), out)
				break
			}
		}

		resChan <- nil
	}(m)

	timer := time.NewTimer(60 * time.Second) // TODO - make configurable
	select {
	case res := <-resChan:
		return res
	case <-timer.C:
		return fmt.Errorf("Unable to verify docker engine on %s within timeout", m.GetName())
	}
}

// Return the public IP of the machine
func (m *VirshMachine) GetIP() (string, error) {
	for m.ip == "" { // TODO timeout if this hangs indefinitely...
		ipRegex := regexp.MustCompile(`ipv4\s+([^/]+)`)
		cmd := exec.Command("virsh", "-q", "domifaddr", m.GetName())
		data, err := cmd.CombinedOutput()
		out := strings.TrimSpace(string(data))
		if err == nil {
			lines := strings.Split(string(out), "\n")

			if len(lines) > 0 {
				matches := ipRegex.FindStringSubmatch(lines[0])
				if len(matches) > 0 {
					ip := matches[1]
					m.ip = ip
					m.internalip = ip
					m.dockerHost = fmt.Sprintf("tcp://%s:2376", ip)
					// TODO validate the IP looks good
					break
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	return m.ip, nil
}

// Get the internal IP (useful for join operations)
func (m *VirshMachine) GetInternalIP() (string, error) {
	return m.internalip, nil
}

// MachineSSH runs an ssh command and returns a string of the combined stdout/stderr output once done
func (m *VirshMachine) MachineSSH(command string) (string, error) {
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
	}
	if m.sshKeyPath != "" {
		args = append(args, "-i", m.sshKeyPath)
	}
	args = append(args, m.sshUser+"@"+m.ip, command)
	log.Debugf("SSH to %s: %v", m.MachineName, args)
	cmd := exec.Command(args[0], args[1:]...)
	tty, err := pty.Start(cmd)
	if err != nil {
		log.Debugf("Failed to establish tty for ssh command: %s", err)
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

// Get the contents of a specific file on the engine
func (m *VirshMachine) CatHostFile(hostPath string) ([]byte, error) {
	return CatHostFile(m, hostPath)
}

// Get the content of a directory as a tar file from the engine
func (m *VirshMachine) TarHostDir(hostPath string) ([]byte, error) {
	return TarHostDir(m, hostPath)
}

// IsWindows reports if this machines is a windows system - false means linux
func (m *VirshMachine) IsWindows() bool {
	return m.isWindows
}

// Write data from an io.Reader to a file on the machine with 0600 perms.
func (m *VirshMachine) WriteFile(filePath string, data io.Reader) error {
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
	return m.writeLocalFile(f.Name(), filePath)
}

func (m *VirshMachine) writeLocalFile(localFilePath, remoteFilePath string) error {
	args := []string{
		"scp", "-q",
		"-o", "StrictHostKeyChecking=no",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "VerifyHostKeyDNS=no",
	}
	if m.sshKeyPath != "" {
		args = append(args, "-i", m.sshKeyPath)
	}
	args = append(args, localFilePath, fmt.Sprintf("%s@%s:%s", m.sshUser, m.ip, remoteFilePath))
	cmd := exec.Command(args[0], args[1:]...)
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if out != "" {
		log.Debug(out)
	}
	if err != nil {
		log.Error(string(out))
		return err
	}
	return nil
}

func (m *VirshMachine) GetConnectionEnv() string {
	lines := []string{
		fmt.Sprintf(`export DOCKER_HOST="tcp://%s:2376"`, m.ip),
		fmt.Sprintf(`export DOCKER_CERT_PATH="%s"`, VirshDiskDir),
		"export DOCKER_TLS_VERIFY=1",
		fmt.Sprintf("# %s", m.MachineName),
	}
	if m.sshKeyPath != "" {
		lines = append(lines, fmt.Sprintf("# ssh -i %s %s@%s", m.sshKeyPath, m.sshUser, m.ip))
	} else {
		lines = append(lines, fmt.Sprintf("# ssh %s@%s", m.sshUser, m.ip))
	}
	return strings.Join(lines, "\n")
}
