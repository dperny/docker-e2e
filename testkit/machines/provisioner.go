package machines

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
)

var (
	EngineInstallURL    = os.Getenv("ENGINE_INSTALL_URL")
	EngineInstallWinURL = os.Getenv("ENGINE_INSTALL_WIN_URL")
	EngineInstallCMD    = os.Getenv("ENGINE_INSTALL_CMD")
	TCPPortList         = []int{
		// Product ports
		443, 2377, 2376, 4789, 7946, 12382, 12386, 12383, 12379, 12380, 12376, 12381, 12385, 12384, 12387,

		// Test rigging ports
		389,  // LDAP tests
		3376, // The port we configure classic swarm on so the tests are compatible with docker-machine
		8443, // Alternate port for controller used for some tests
	}
	UDPPortList = []int{
		7946,
	}

	// Note: we can't use the hosts list, because the init system specifies -H and refuses to accept both
	daemonJSON = map[string]interface{}{
		"debug":     true,
		"tls":       true,
		"tlscacert": "/etc/docker/ca.pem",
		"tlscert":   "/etc/docker/cert.pem",
		"tlskey":    "/etc/docker/key.pem",
		"tlsverify": true,
	}
)

func getServerVersion(m Machine) (string, error) {
	// During bootup, docker might take a while to start, so check to see if it looks like it's there
	out, err := m.MachineSSH("docker --version")
	if err != nil {
		log.Debugf("Failed to check docker version: %s: %s", err, out)
		return "", err
	}
	// So the client is present...
	dclient, err := m.GetEngineAPIWithTimeout(2 * time.Second) // Very short timeout so we don't waste time
	if err != nil {
		return "", fmt.Errorf("Failed to get engine client: %s", err)
	}
	deadline := time.Now().Add(20 * time.Second) // How long should we wait?
	var lastErr error
	for time.Now().Before(deadline) {
		version, err := dclient.ServerVersion(context.Background())
		if err == nil {
			return version.Version, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("Failed to get engine version before timing out: %s", lastErr)

}

// VerifyDockerEngine makes sure the machine has docker installed, and if not
// will install the docker daemon
func VerifyDockerEngine(m Machine, localCertDir string) error {
	log.Debugf("Verifying or installing docker engine on %s", m.GetName())

	resChan := make(chan error)
	ip, err := m.GetIP()
	if err != nil {
		return err
	}
	internalIP, err := m.GetInternalIP()
	if err != nil {
		return err
	}

	go func(m Machine) {

		// First check to see if docker is already installed
		ver, err := getServerVersion(m)
		if err != nil {
			// If the engine's not installed, then they have to specify CMD or URL (fail fast if not specified)
			if EngineInstallCMD == "" && EngineInstallURL == "" {
				resChan <- fmt.Errorf("Base disk does not appear to have an engine installed, so you must specify ENGINE_INSTALL_URL or ENGINE_INSTALL_CMD to use it")
				return
			}

			// Install the engine
			out, err := m.MachineSSH("sudo mkdir -p /etc/docker; sudo chown docker /etc/docker")
			if err != nil {
				resChan <- fmt.Errorf("Failed to create /etc/docker on %s: %s: %s", m.GetName(), err, out)
				return
			}

			// Check to see if we have devicemapper set up
			out, err = m.MachineSSH("sudo vgs docker")
			if err == nil {
				log.Debugf("device-mapper detected - status is\n%s", out)
				// Update the daemonJSON to include the device mapper settings
				daemonJSON["storage-driver"] = "devicemapper"
				daemonJSON["storage-opts"] = []string{
					"dm.thinpooldev=/dev/mapper/docker-thinpool",
					"dm.use_deferred_removal=true",
					"dm.use_deferred_deletion=true",
				}
			} else {
				log.Debugf("device-mapper not detected: %s: %s", err, out)

				// No device mapper, check for ZFS
				out, err = m.MachineSSH("sudo zfs list -t all")
				if err == nil {
					log.Debugf("zfs detected - status is\n%s", out)
					// Update the daemonJSON to include the ZFS mapper settings
					daemonJSON["storage-driver"] = "zfs"
				} else {
					log.Debugf("zfs not detected: %s: %s", err, out)
				}
			}

			// Check for SELinux, and make the daemon enforce since that's what customers do...
			out, err = m.MachineSSH("sudo getenforce")
			if err == nil {
				if strings.ToLower(strings.TrimSpace(out)) == "enforcing" {
					log.Debug("Detected SELinux in enforcing mode")
					daemonJSON["selinux-enabled"] = true
				}
			}

			data, err := json.Marshal(daemonJSON)
			if err != nil {
				resChan <- fmt.Errorf("Failed to generate daemon.json for %s: %s - %#v", m.GetName(), err, daemonJSON)
				return
			}

			err = m.WriteFile("/etc/docker/daemon.json", bytes.NewBuffer(data))
			if err != nil {
				resChan <- fmt.Errorf("Failed to write daemon.json to %s: %s", m.GetName(), err)
				return
			}

			ca, cert, key, err := GenerateNodeCerts(localCertDir, m.GetName(), []string{ip, internalIP, m.GetName()})
			if err != nil {
				resChan <- fmt.Errorf("Failed to write cert locally: %s", err)
				return
			}
			cabuf := bytes.NewBuffer(ca)
			err = m.WriteFile("/etc/docker/ca.pem", cabuf)
			if err != nil {
				resChan <- fmt.Errorf("Failed to write ca.pem to %s: %s", m.GetName(), err)
				return
			}
			certbuf := bytes.NewBuffer(cert)
			err = m.WriteFile("/etc/docker/cert.pem", certbuf)
			if err != nil {
				resChan <- fmt.Errorf("Failed to write cert.pem to %s: %s", m.GetName(), err)
				return
			}
			keybuf := bytes.NewBuffer(key)
			err = m.WriteFile("/etc/docker/key.pem", keybuf)
			if err != nil {
				resChan <- fmt.Errorf("Failed to write key.pem to %s: %s", m.GetName(), err)
				return
			}

			installCMD := EngineInstallCMD
			if installCMD == "" {
				installCMD = fmt.Sprintf("curl -sSL %s | sh", EngineInstallURL)
			}
			out, err = m.MachineSSH(installCMD)
			if err != nil {
				log.Info(out)
				resChan <- fmt.Errorf("Failed to install engine on %s: %s", m.GetName(), err)
				return
			}

			// XXX Might not be necessary...
			time.Sleep(500 * time.Millisecond)

			// But we're not done :-(
			// BLECH!  This'll need some refinement to handle different variants...
			out, err = m.MachineSSH("systemctl show --property=FragmentPath docker 2>&1 | grep FragmentPath | cut -f2 -d=")
			if err != nil {
				resChan <- fmt.Errorf("Couldn't figure out the systemctl config for docker daemon - need to add suport for this distro...: %s: %s", err, out)
				return
			}
			cfgFile := strings.TrimSpace(out)

			out, err = m.MachineSSH(`sudo sed -i -e 's|^ExecStart=\(.*\)$|ExecStart=\1 -H unix:// -H tcp://0.0.0.0:2376|g' ` + cfgFile)
			if err != nil {
				resChan <- fmt.Errorf("Failed to update config file: %s: %s", err, out)
				return
			}
			out, err = m.MachineSSH("sudo systemctl daemon-reload")
			if err != nil {
				resChan <- fmt.Errorf("Couldn't restart docker daemon...: %s: %s", err, out)
				return
			}
			// Check to see if firewalld is enabled, and if so, punch a hole
			_, err = m.MachineSSH("systemctl status firewalld")
			if err == nil {
				log.Debugf("Detected firewalld, opening port")
				for _, port := range TCPPortList {
					out, err = m.MachineSSH(fmt.Sprintf("sudo firewall-cmd --add-port=%d/tcp --permanent", port))
					if err != nil {
						log.Warnf("Firewall NOT opened TCP: %d %s %s", port, err, out)
					}
				}
				for _, port := range UDPPortList {
					out, err = m.MachineSSH(fmt.Sprintf("sudo firewall-cmd --add-port=%d/udp --permanent", port))
					if err != nil {
						log.Warnf("Firewall NOT opened UDP: %d %s %s", port, err, out)
					}
				}
				out, err = m.MachineSSH("sudo firewall-cmd --reload")
				if err != nil {
					log.Warnf("Firewall NOT restarted: %s %s", err, out)
				}
			} else {
				_, err = m.MachineSSH("sudo SuSEfirewall2 status")
				if err == nil {
					log.Debugf("Detected SuSEfirewall2, opening ports")
					for _, port := range TCPPortList {
						out, err = m.MachineSSH(fmt.Sprintf("sudo SuSEfirewall2 open EXT TCP %d", port))
						if err != nil {
							log.Warnf("Firewall NOT opened for TCP %d: %s %s", port, err, out)
						}
					}
					for _, port := range UDPPortList {
						out, err = m.MachineSSH(fmt.Sprintf("sudo SuSEfirewall2 open EXT UDP %d", port))
						if err != nil {
							log.Warnf("Firewall NOT opened for UDP %d: %s %s", port, err, out)
						}
					}
					out, err = m.MachineSSH("sudo SuSEfirewall2 start")
					log.Debug("Firewall restarted: %s %s", out, err)
				}
			}
			out, err = m.MachineSSH("sudo systemctl restart docker.service")
			if err != nil {
				resChan <- fmt.Errorf("Couldn't restart docker daemon...: %s: %s", err, out)
				return
			}

			// End hacky daemon config goop

			// Now wait for the daemon to start responding...
			for {
				ver, err = getServerVersion(m)
				if err == nil {
					log.Infof("Succesfully installed engine %s on %s", ver, m.GetName())
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
		} else {
			// Make sure to bounce the daemon so it has the right hostname since we likely just set it
			out, err := m.MachineSSH("sudo systemctl restart docker.service")
			if err != nil {
				resChan <- fmt.Errorf("Couldn't restart docker daemon...: %s: %s", err, out)
				return
			}
		}
		log.Debugf("engine on %s is ready", m.GetName())
		resChan <- nil

	}(m)

	timer := time.NewTimer(5 * time.Minute) // TODO - make configurable
	select {
	case res := <-resChan:
		return res
	case <-timer.C:
		return fmt.Errorf("Unable to verify docker engine on %s within timeout", m.GetName())
	}

	return nil
}

// VerifyDockerEngineWindows makes sure the machine has docker installed, and if not
// will install the docker daemon
func VerifyDockerEngineWindows(m Machine, localCertDir string) error {
	log.Debugf("Verifying or installing docker engine on windows machine %s", m.GetName())

	resChan := make(chan error, 1)

	ip, err := m.GetIP()
	if err != nil {
		return err
	}
	internalIP, err := m.GetInternalIP()
	if err != nil {
		return err
	}

	go func(m Machine) {

		// First check to see if docker is already installed
		ver, err := getServerVersion(m)
		if err != nil {
			// If the engine's not installed, then they have to specify CMD or URL (fail fast if not specified)
			if EngineInstallWinURL == "" {
				resChan <- fmt.Errorf("Base disk does not appear to have an engine installed, so you must specify ENGINE_INSTALL_WIN_URL to use it")
				return
			}

			// TODO - why do we sometimes get "lost connection" or just simply hangs for no apparent reason
			time.Sleep(500 * time.Millisecond)

			out, err := m.MachineSSH(fmt.Sprintf(`powershell Invoke-WebRequest "%s" -UseBasicParsing -OutFile docker.zip`, EngineInstallWinURL))
			if err != nil {
				resChan <- fmt.Errorf("Failed to download engine from %s: %s: %s", EngineInstallWinURL, m.GetName(), err, out)
				return
			}

			// TODO - why do we sometimes get "lost connection"
			time.Sleep(500 * time.Millisecond)

			out, err = m.MachineSSH("powershell Expand-Archive docker.zip -DestinationPath $Env:ProgramFiles")
			if err != nil {
				resChan <- fmt.Errorf("Failed to extract engine %s: %s", m.GetName(), err, out)
				return
			}

			// TODO - why do we sometimes get "lost connection"
			time.Sleep(500 * time.Millisecond)

			out, err = m.MachineSSH("powershell Remove-Item -Force docker.zip")
			if err != nil {
				resChan <- fmt.Errorf("Failed to cleanup zip %s: %s", m.GetName(), err, out)
				return
			}

			// TODO - why do we sometimes get "lost connection"
			time.Sleep(500 * time.Millisecond)

			// Modify the daemonJSON paths for windows
			daemonJSON["tlscacert"] = `c:\ProgramData\docker\ca.pem`
			daemonJSON["tlscert"] = `c:\ProgramData\docker\cert.pem`
			daemonJSON["tlskey"] = `c:\ProgramData\docker\key.pem`
			data, err := json.Marshal(daemonJSON)
			if err != nil {
				resChan <- fmt.Errorf("Failed to generate daemon.json for %s: %s - %#v", m.GetName(), err, daemonJSON)
				return
			}
			// Make sure the path exists
			out, err = m.MachineSSH(`powershell mkdir c:\ProgramData\docker\config`)
			if err != nil {
				resChan <- fmt.Errorf("Failed to create config dir %s: %s", m.GetName(), err, out)
				return
			}

			err = m.WriteFile(`c:\ProgramData\docker\config\daemon.json`, bytes.NewBuffer(data))
			if err != nil {
				resChan <- fmt.Errorf("Failed to write daemon.json to %s: %s", m.GetName(), err)
				return
			}

			out, err = m.MachineSSH(`powershell mkdir c:\ProgramData\docker\daemoncerts`)
			if err != nil {
				resChan <- fmt.Errorf("Failed to create daemoncerts dir %s: %s", m.GetName(), err, out)
				return
			}
			ca, cert, key, err := GenerateNodeCerts(localCertDir, m.GetName(), []string{ip, internalIP, m.GetName()})
			if err != nil {
				resChan <- fmt.Errorf("Failed to write cert locally: %s", err)
				return
			}
			cabuf := bytes.NewBuffer(ca)
			err = m.WriteFile(`c:\ProgramData\docker\daemoncerts\ca.pem`, cabuf)
			if err != nil {
				resChan <- fmt.Errorf("Failed to write ca.pem to %s: %s", m.GetName(), err)
				return
			}
			certbuf := bytes.NewBuffer(cert)
			err = m.WriteFile(`c:\ProgramData\docker\daemoncerts\cert.pem`, certbuf)
			if err != nil {
				resChan <- fmt.Errorf("Failed to write cert.pem to %s: %s", m.GetName(), err)
				return
			}
			keybuf := bytes.NewBuffer(key)
			err = m.WriteFile(`c:\ProgramData\docker\daemoncerts\key.pem`, keybuf)
			if err != nil {
				resChan <- fmt.Errorf("Failed to write key.pem to %s: %s", m.GetName(), err)
				return
			}

			out, err = m.MachineSSH("powershell dockerd.exe -H npipe:////./pipe/docker_engine -H 0.0.0.0:2376 --register-service")
			if err != nil {
				resChan <- fmt.Errorf("Failed to setup service %s: %s", m.GetName(), err, out)
				return
			}

			// Open up the necessary ports in the firewall
			log.Debugf("Opening firewall ports")
			for _, port := range TCPPortList {
				out, err = m.MachineSSH(fmt.Sprintf(`powershell netsh advfirewall firewall add rule name="%d-TCP" dir=in action=allow protocol=TCP localport=%d`, port, port))
				if err != nil {
					log.Warnf("Firewall NOT opened TCP: %d %s %s", port, err, out)
				}
			}
			for _, port := range UDPPortList {
				out, err = m.MachineSSH(fmt.Sprintf(`powershell netsh advfirewall firewall add rule name="%d-UDP" dir=in action=allow protocol=UDP localport=%d`, port, port))
				if err != nil {
					log.Warnf("Firewall NOT opened UDP: %d %s %s", port, err, out)
				}
			}

			out, err = m.MachineSSH("powershell set-service docker -startuptype automatic")
			if err != nil {
				resChan <- fmt.Errorf("Failed to set service to automatic %s: %s", m.GetName(), err, out)
				return
			}
			out, err = m.MachineSSH("powershell Start-Service docker")
			if err != nil {
				resChan <- fmt.Errorf("Failed to start docker service %s: %s", m.GetName(), err, out)
				return
			}

			// Now wait for the daemon to start responding...
			for {
				ver, err = getServerVersion(m)
				if err == nil {
					log.Infof("Succesfully installed engine %s on %s", ver, m.GetName())
					break
				} else {
					log.Debugf("Error getting version: %s", err)
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
		log.Debugf("engine on %s is ready", m.GetName())
		resChan <- nil

	}(m)

	timer := time.NewTimer(2 * time.Minute) // TODO - make configurable
	select {
	case res := <-resChan:
		return res
	case <-timer.C:
		return fmt.Errorf("Unable to verify docker engine on %s within timeout", m.GetName())
	}

	return nil
}
