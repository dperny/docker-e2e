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
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/client"
	"github.com/kr/pty"
)

var (
	VBoxDiskDir         string        // TODO Default path? (shouldn't be in the orca tree!)
	VBoxOSLinux         = "centos7.0" // default
	VBoxOSTypeLinuxDict = map[string]string{
		"rhel7.3":     "RedHat_64",
		"ubuntu16.04": "Ubuntu_64",
		"centos7.0":   "RedHat_64",
	}
	VBoxOSWindows     = "winnanors1"
	VBoxOSTypeWindows = "WindowsNT_64"
	vbm               = "VBoxManage"
)

type VBoxMachine struct {
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
	VBoxDiskDir = os.Getenv("VBOX_DISK_DIR")
	baseOSLinux := os.Getenv("VBOX_OS_LINUX")
	if baseOSLinux != "" {
		if _, ok := VBoxOSTypeLinuxDict[baseOSLinux]; ok {
			VBoxOSLinux = baseOSLinux
		} else {
			log.Warnf("Unsupported VBOX_OS %s, using default %s", baseOSLinux, VBoxOSLinux)
		}
	}
	baseOSWindows := os.Getenv("VBOX_OS_WINDOWS")
	if baseOSWindows != "" {
		VBoxOSWindows = baseOSWindows
	}
}

func getVBoxActiveMachines() []string {
	cmd := exec.Command(vbm, "list", "runningvms")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Info("Failed to get list - assuming no VMs: %s", err)
	}

	machines := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		s := strings.SplitN(line, `"`, 3)
		if len(s) == 3 {
			machines = append(machines, s[1])
		}
	}
	return machines
}

func NewVBoxMachines(linuxCount, windowsCount int) ([]Machine, []Machine, error) {

	if VBoxDiskDir == "" {
		return nil, nil, fmt.Errorf("To use the vbox driver, you must set VBOX_DISK_DIR to point to where your base OS disks and ssh key live")
	}

	baseOSLinux := filepath.Join(VBoxDiskDir, VBoxOSLinux+".vdi")
	baseOSWindows := filepath.Join(VBoxDiskDir, VBoxOSWindows+".vdi")

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

	timer := time.NewTimer(60 * time.Minute) // TODO - make configurable
	errChan := make(chan error)
	resChan := make(chan []*VBoxMachine)

	go func() {
		log.Debugf("Attempting %s machine creation for %d nodes", VBoxOSLinux, linuxCount)
		id, _ := rand.Int(rand.Reader, big.NewInt(0xffffff))
		linuxMachines := []*VBoxMachine{}
		windowsMachines := []*VBoxMachine{}

		index := 0
		for ; index < linuxCount; index++ {
			m := &VBoxMachine{
				MachineName: fmt.Sprintf("%s-%X-%d", NamePrefix, id, index),
				BaseDisk:    baseOSLinux,
				CPUCount:    1,        // TODO - make configurable
				Memory:      2048,     // TODO - make configurable
				sshUser:     "docker", // TODO - make configurable
				sshKeyPath:  filepath.Join(VBoxDiskDir, "id_rsa"),
				DiskType:    "sata",
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
			cert, err := tls.LoadX509KeyPair(filepath.Join(VBoxDiskDir, "cert.pem"), filepath.Join(VBoxDiskDir, "key.pem"))
			if err != nil {
				errChan <- err
				return
			}
			caCert, err := ioutil.ReadFile(filepath.Join(VBoxDiskDir, "ca.pem"))
			if err != nil {
				errChan <- err
				return
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			m.tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,

				// NOTE:This is insecure, but the test VMs have a short-lifespan
				InsecureSkipVerify: true, // We don't verify so we can recyle the same certs regardless of VM IP

			}
			linuxMachines = append(linuxMachines, m)
		}

		log.Debugf("Creating %d windows VMs based on %s", windowsCount, VBoxOSWindows)
		for ; index-linuxCount < windowsCount; index++ {
			m := &VBoxMachine{
				MachineName: fmt.Sprintf("%s-%X-%d", NamePrefix, id, index),
				BaseDisk:    baseOSWindows,
				CPUCount:    1,        // TODO - make configurable
				Memory:      2048,     // TODO - make configurable
				sshUser:     "docker", // TODO - make configurable
				sshKeyPath:  filepath.Join(VBoxDiskDir, "id_rsa"),
				DiskType:    "ide",
				NICType:     "82540EM",
			}
			if err := m.cloneDisk(); err != nil {
				errChan <- err
				return
			}
			if err := m.defineWindows(); err != nil {
				errChan <- err
				return
			}
			if err := m.Start(); err != nil {
				errChan <- err
				return
			}
			cert, err := tls.LoadX509KeyPair(filepath.Join(VBoxDiskDir, "cert.pem"), filepath.Join(VBoxDiskDir, "key.pem"))
			if err != nil {
				errChan <- err
				return
			}
			caCert, err := ioutil.ReadFile(filepath.Join(VBoxDiskDir, "ca.pem"))
			if err != nil {
				errChan <- err
				return
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			m.tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,

				// NOTE:This is insecure, but the test VMs have a short-lifespan
				InsecureSkipVerify: true, // We don't verify so we can recyle the same certs regardless of VM IP

			}
			windowsMachines = append(windowsMachines, m)
		}

		var wg sync.WaitGroup

		res := []*VBoxMachine{}
		machineErrChan := make(chan error, linuxCount+windowsCount)
		for _, m := range linuxMachines {
			wg.Add(1)
			go func(m *VBoxMachine) {
				var result error
				// Set the hostname
				out, err := m.MachineSSH(
					fmt.Sprintf(`sudo hostname "%s"; sudo sed -e 's/.*/%s/' -i /etc/hostname`,
						m.GetName(), m.GetName()))
				if err != nil {
					log.Warnf("Failed to set hostname to %s: %s: %s", m.GetName(), err, out)
				}

				result = VerifyDockerEngine(m, VBoxDiskDir)

				machineErrChan <- result
				wg.Done()
			}(m)
			res = append(res, m)
		}
		for _, m := range windowsMachines {
			wg.Add(1)
			go func(m *VBoxMachine) {
				var result error
				out, err := m.MachineSSH(
					fmt.Sprintf(`powershell rename-computer -newname "%s" -restart`, m.GetName()))
				if err != nil {
					log.Warnf("Failed to set hostname to %s: %s: %s", m.GetName(), err, out)
				}
				// Give it a few seconds to reboot before we start hammering on it...
				time.Sleep(5 * time.Second) // TODO - need a better way to tell if we've finished the reboot
				result = VerifyDockerEngineWindows(m, VBoxDiskDir)
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
				//Detected errors, destroy all the machines we created
				for _, m := range linuxMachines {
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
		return linuxMachines, nil, nil
	case err := <-errChan:
		return nil, nil, err
	case <-timer.C:
		return nil, nil, fmt.Errorf("Unable to create %d machines within timeout", linuxCount)
	}
}

func (m *VBoxMachine) cloneDisk() error {
	dir := path.Dir(m.BaseDisk)
	linkedCloneName := filepath.Join(dir, m.MachineName+".vdi")
	if _, err := os.Stat(linkedCloneName); err == nil {
		return fmt.Errorf("Linked clone %s of base disk %s already exists!", linkedCloneName, m.BaseDisk)
	}
	log.Debugf("Creating linked clone %s with base disk %s", linkedCloneName, m.BaseDisk)
	cmd := exec.Command(vbm, "clonemedium", m.BaseDisk, linkedCloneName)

	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to create linked clone %s on %s: %s: %s", linkedCloneName, m.BaseDisk, out, err)
	}
	log.Debug(out)
	m.DiskPath = linkedCloneName
	return nil
}

func (m *VBoxMachine) define() error {
	log.Debugf("Creating vm %s", m.MachineName)

	cmd := exec.Command(vbm, "createvm", "--name", m.MachineName, "--register")
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to createvm %s: %s: %s", m.MachineName, err, out)
	}

	log.Debugf("Setting OS type to %s", VBoxOSTypeLinuxDict[VBoxOSLinux])
	cmd = exec.Command(vbm, "modifyvm", m.MachineName, "--ostype", VBoxOSTypeLinuxDict[VBoxOSLinux])
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to change vm ostype %s: %s: %s: %s", m.MachineName, VBoxOSTypeLinuxDict[VBoxOSLinux], err, out)
	}

	cmd = exec.Command(vbm, "modifyvm", m.MachineName, "--memory", strconv.Itoa(m.Memory))
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to change vm memory %s: %s: %s:", m.MachineName, err, out)
	}

	diskName := "SATA"
	cmd = exec.Command(vbm, "storagectl", m.MachineName, "--name", diskName, "--add", m.DiskType, "--controller", "IntelAHCI", "--bootable", "on")
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to add vm storage ctl %s: %s: %s", m.MachineName, err, out)
	}

	log.Debugf("Attaching storage at %s", m.DiskPath)
	cmd = exec.Command(vbm, "storageattach", m.MachineName, "--storagectl", diskName, "--port", "0", "--device", "0", "--type", "hdd", "--medium", m.DiskPath)
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to attach vm storage %s: %s: %s: %s", m.MachineName, m.DiskPath, err, out)
	}

	log.Debug("Setting network")

	cmd = exec.Command(vbm, "modifyvm", m.MachineName, "--nic1", "nat", "--nictype1", m.NICType, "--cableconnected1", "on")
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to set up network (nat) %s: %s: %s", m.MachineName, err, out)
	}

	cmd = exec.Command(vbm, "modifyvm", m.MachineName, "--nic2", "hostonly", "--nictype2", m.NICType, "--hostonlyadapter2", "vboxnet0", "--cableconnected2", "on")
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to set up network (hostonly) %s: %s: %s", m.MachineName, err, out)
	}

	log.Debugf("Creating vm %s successful, ready to start", m.MachineName)
	return nil
}

func (m *VBoxMachine) defineWindows() error {
	log.Debugf("Creating vm %s", m.MachineName)

	cmd := exec.Command(vbm, "createvm", "--name", m.MachineName, "--register")
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to createvm %s: %s: %s", m.MachineName, err, out)
	}

	log.Debugf("Setting OS type to %s", VBoxOSTypeWindows)
	cmd = exec.Command(vbm, "modifyvm", m.MachineName, "--ostype", VBoxOSTypeWindows)
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to change vm ostype %s: %s: %s: %s", m.MachineName, VBoxOSTypeWindows, err, out)
	}

	cmd = exec.Command(vbm, "modifyvm", m.MachineName, "--memory", strconv.Itoa(m.Memory))
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to change vm memory %s: %s: %s:", m.MachineName, err, out)
	}

	diskName := "IDE"
	cmd = exec.Command(vbm, "storagectl", m.MachineName, "--name", diskName, "--add", m.DiskType, "--controller", "PIIX4", "--bootable", "on")
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to add vm storage ctl %s: %s: %s", m.MachineName, err, out)
	}

	log.Debugf("Attaching storage at %s", m.DiskPath)
	cmd = exec.Command(vbm, "storageattach", m.MachineName, "--storagectl", diskName, "--port", "0", "--device", "0", "--type", "hdd", "--medium", m.DiskPath)
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to attach vm storage %s: %s: %s: %s", m.MachineName, m.DiskPath, err, out)
	}

	cmd = exec.Command(vbm, "modifyvm", m.MachineName, "--ioapic", "on")
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to turn on ioapic %s: %s: %s", m.MachineName, err, out)
	}

	log.Debug("Setting network")

	cmd = exec.Command(vbm, "modifyvm", m.MachineName, "--nic1", "nat", "--nictype1", m.NICType, "--cableconnected1", "on")
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to set up network (nat) %s: %s: %s", m.MachineName, err, out)
	}

	cmd = exec.Command(vbm, "modifyvm", m.MachineName, "--nic2", "hostonly", "--nictype2", m.NICType, "--hostonlyadapter2", "vboxnet0", "--cableconnected2", "on")
	data, err = cmd.CombinedOutput()
	out = strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to set up network (hostonly) %s: %s: %s", m.MachineName, err, out)
	}

	log.Debugf("Creating vm %s successful, ready to start", m.MachineName)
	return nil
}

// GetName retrieves the machines name
func (m *VBoxMachine) GetName() string {
	return m.MachineName
}

// GetDockerHost reports the machines docker host
func (m *VBoxMachine) GetDockerHost() string {
	return m.dockerHost
}

// GetEngineAPIWithTimeout gets an engine API client with a default timeout
func (m *VBoxMachine) GetEngineAPI() (*client.Client, error) {
	return m.GetEngineAPIWithTimeout(Timeout)
}

// GetEngineAPIWithTimeout gets an engine API client with a timeout set
func (m *VBoxMachine) GetEngineAPIWithTimeout(timeout time.Duration) (*client.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: m.tlsConfig,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	version := "" //TODO
	return client.NewClient(m.dockerHost, version, httpClient, nil)
}

// IsRunning returns true if this machine is currently running
func (m *VBoxMachine) IsRunning() bool {
	names := getVBoxActiveMachines()

	for _, name := range names {
		if m.MachineName == name {
			return true
		}

	}
	return false
}

// Remove the machine after the tests have completed
func (m *VBoxMachine) Remove() error {
	if os.Getenv("PRESERVE_TEST_MACHINE") != "" {
		log.Infof("Skipping removal of machine %s with PRESERVE_TEST_MACHINE set", m.GetName())
		return nil
	}
	if m.IsRunning() {
		m.Kill()
	}

	cmd := exec.Command(vbm, "unregistervm", m.MachineName, "--delete")
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

// Remove the machine after the tests have completed
func (m *VBoxMachine) RemoveAndPreserveDisk() error {
	if os.Getenv("PRESERVE_TEST_MACHINE") != "" {
		log.Infof("Skipping removal of machine %s with PRESERVE_TEST_MACHINE set", m.GetName())
		return nil
	}
	if m.IsRunning() {
		m.Stop()
	}

	cmd := exec.Command(vbm, "unregistervm", m.MachineName)
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
func (m *VBoxMachine) Stop() error {
	//TODO: make it gracefully shutdown
	cmd := exec.Command(vbm, "controlvm", m.MachineName, "poweroff")

	//cmd := exec.Command(vbm, "controlvm", m.MachineName, "acpipowerbutton")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}
	return nil
}

// Kill forcefully stops the virtual machine (likely to corrupt the machine, so
// do not use this if you intend to start the machine again)
func (m *VBoxMachine) Kill() error {
	cmd := exec.Command(vbm, "controlvm", m.MachineName, "poweroff")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(string(out))
		return err
	}

	// Make sure it's stopped before returning...
	resChan := make(chan error)

	go func(m *VBoxMachine) {
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
		return fmt.Errorf("Unable to verify docker engine on %s within timeout", m.MachineName)
	}
}

// Start powers on the VM
func (m *VBoxMachine) Start() error {

	cmd := exec.Command(vbm, "startvm", m.MachineName, "--type", "headless")
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		return fmt.Errorf("Failed to start vm %s: %s: %s", m.MachineName, err, out)
	}

	resChan := make(chan error)

	ips, err := generateIPs()
	if err != nil {
		return err
	}

	macAddress, err := getMACAddress(m.GetName())

	if err != nil {
		return err
	}
	log.Debugf("MAC address for %s is %s", m.GetName(), macAddress)

	go func(m *VBoxMachine) {

		log.Debugf("Waiting for IP to appear for %s", m.GetName())
		for {
			// Dial to all the IPs that is configured in vboxnet0.
			for _, ip := range ips {
				conn, err := net.DialTimeout("tcp", ip+":22", time.Duration(1)*time.Millisecond)
				if err == nil {
					conn.Close()
				}
			}

			ip, err := findIPFromMAC(macAddress)
			if err == nil {
				m.ip = ip
				m.internalip = ip
				m.dockerHost = fmt.Sprintf("tcp://%s:2376", ip)
				break
			}

			time.Sleep(1 * time.Second)
		}
		log.Debugf("Machine %s has IP %s", m.GetName(), m.ip)

		// Loop until we can ssh in
		for {
			out, err := m.MachineSSH("uptime")
			if err != nil && strings.Contains(out, "is not recognized as an internal or external command") {
				log.Info("Detected windows image booted")
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
func (m *VBoxMachine) GetIP() (string, error) {
	return m.ip, nil
}

// Get the internal IP (useful for join operations)
func (m *VBoxMachine) GetInternalIP() (string, error) {
	return m.internalip, nil
}

// MachineSSH runs an ssh command and returns a string of the combined stdout/stderr output once done
func (m *VBoxMachine) MachineSSH(command string) (string, error) {
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
		"-i", m.sshKeyPath,
		m.sshUser + "@" + m.ip,
		command,
	}
	log.Debugf("SSH to %s: %v", m.MachineName, args)
	cmd := exec.Command(args[0], args[1:]...)
	tty, err := pty.Start(cmd)
	if err != nil {
		log.Debugf("Failed to establish tty for ssh command")
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
func (m *VBoxMachine) CatHostFile(hostPath string) ([]byte, error) {
	return CatHostFile(m, hostPath)
}

// Get the content of a directory as a tar file from the engine
func (m *VBoxMachine) TarHostDir(hostPath string) ([]byte, error) {
	return TarHostDir(m, hostPath)
}

// IsWindows reports if this machines is a windows system - false means linux
func (m *VBoxMachine) IsWindows() bool {
	return m.isWindows
}

// Write data from an io.Reader to a file on the machine with 0600 perms.
func (m *VBoxMachine) WriteFile(filePath string, data io.Reader) error {
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

func (m *VBoxMachine) writeLocalFile(localFilePath, remoteFilePath string) error {
	cmd := exec.Command("scp", "-i", m.sshKeyPath, "-q",
		"-o", "StrictHostKeyChecking=no",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "VerifyHostKeyDNS=no",
		localFilePath,
		fmt.Sprintf("%s@%s:%s", m.sshUser, m.ip, remoteFilePath))
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

func getMACAddress(vmname string) (string, error) {
	cmd := exec.Command("VBoxManage", "showvminfo", vmname, "--machinereadable")
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		return "", err
	}
	lines := strings.Split(out, "\n")
	m := make(map[string]string)
	for _, line := range lines {
		w := strings.Split(line, "=")
		m[w[0]] = w[1]
	}

	for i := 1; i <= 8; i++ {
		if m["nic"+strconv.Itoa(i)] == `"hostonly"` && m["hostonlyadapter"+strconv.Itoa(i)] == `"vboxnet0"` {
			s := m["macaddress"+strconv.Itoa(i)]
			if len(s) != 14 {
				return "", fmt.Errorf("invalid mac address %s", s)
			}
			// Converts the MAC address in the format of 080027F44E3F to 8:0:27:f4:4e:3f
			b := []string{s[1:3], s[3:5], s[5:7], s[7:9], s[9:11], s[11:13]}
			for i := range b {
				b[i] = strings.ToLower(b[i])
				if b[i][0:1] == "0" {
					b[i] = b[i][1:2]
				}

			}
			return strings.Join(b, ":"), nil
		}
	}
	return "", errors.New("unable to find mac address")

}
func generateIPs() ([]string, error) {
	cmd := exec.Command("VBoxManage", "list", "dhcpservers")
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		return nil, err
	}

	blocks := strings.Split(out, "\n\n")
	dhcpServers := make([]map[string]string, len(blocks))
	for i, block := range blocks {
		lines := strings.Split(block, "\n")
		dhcpServers[i] = make(map[string]string)
		for _, line := range lines {
			w := strings.Split(line, ":")
			key := strings.TrimSpace(w[0])
			value := strings.TrimSpace(w[1])
			dhcpServers[i][key] = value
		}
	}
	for _, server := range dhcpServers {
		if server["NetworkName"] == "HostInterfaceNetworking-vboxnet0" {
			lower := server["lowerIPAddress"]
			upper := server["upperIPAddress"]
			networkMask := server["NetworkMask"]
			// TODO: support other masks.
			if networkMask != "255.255.255.0" {
				return nil, fmt.Errorf("unsupported network mask %s", networkMask)
			}
			lowerIP := net.ParseIP(lower).To4()
			upperIP := net.ParseIP(upper).To4()

			ips := []string{lowerIP.String()}
			ip := lowerIP
			for !ip.Equal(upperIP) {
				ip[3]++
				ips = append(ips, ip.String())
			}
			return ips, nil

		}
	}
	return nil, errors.New("cannot find hostonly network vboxnet0")
}

func findIPFromMAC(macAddress string) (string, error) {
	cmd := exec.Command("arp", "-a")
	data, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(data))
	if err != nil {
		return "", err
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, macAddress) {
			left := strings.Index(line, "(")
			right := strings.Index(line, ")")
			return line[left+1 : right], nil
		}
	}
	return "", fmt.Errorf("cannot find ip from mac address %s", macAddress)
}
