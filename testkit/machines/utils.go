package machines

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

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
