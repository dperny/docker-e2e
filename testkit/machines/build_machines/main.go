package main

import (
	"fmt"
	"os"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker-e2e/testkit/machines"
)

// Simple utility to build one or more test machines
func main() {
	log.SetLevel(log.DebugLevel)
	if len(os.Args) != 3 {
		log.Fatal("You must specify the number of linux VMs and windows VMS on the command line")
	}
	linuxCount, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	windowsCount, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	lm, wm, err := machines.GetTestMachines(linuxCount, windowsCount)
	if err != nil {
		log.Fatalf("Failure: %s", err)
	}
	for _, m := range lm {
		ip, err := m.GetIP()
		if err != nil {
			log.Fatalf("Failure: %s", err)
		}
		// TODO - this is very virsh specific, needs some refactoring...
		fmt.Printf(`
To use this Linux machine

export DOCKER_HOST="tcp://%s:2376"
export DOCKER_CERT_PATH="%s"

(and use the --tls flag until we get sans wired up properly)

When done:
virsh destroy %s
virsh undefine %s
or
VBoxManage controlvm %s poweroff
VBoxManage unregistervm %s --delete
`, ip, machines.VirshDiskDir, m.GetName(), m.GetName(), m.GetName(), m.GetName())
	}
	for _, m := range wm {
		// TODO - flesh out the windows stuff next...
		ip, err := m.GetIP()
		if err != nil {
			log.Fatalf("Failure: %s", err)
		}
		fmt.Printf(`
To use this Windows machine

export DOCKER_HOST="tcp://%s:2376"
export DOCKER_CERT_PATH="%s"

(and use the --tls flag until we get sans wired up properly)

When done:
virsh destroy %s
virsh undefine %s
or
VBoxManage controlvm %s poweroff
VBoxManage unregistervm %s --delete
`, ip, machines.VirshDiskDir, m.GetName(), m.GetName(), m.GetName(), m.GetName())
	}

}
