package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker-e2e/testkit/machines"
)

// Use this utility to periodically take a base image and create various
// specialized images with different engines injected for subsequent testing to
// speed things up so the engine doesn't have to be installed every time The
// goal is to make it "easy" to build these so we can keep the base patched,
// then rapidly re-provision the specialized images.
func main() {
	log.SetLevel(log.DebugLevel)

	linuxMachines, _, err := machines.NewVirshMachines(1, 0)

	if err != nil {
		log.Fatalf("Failure: %s", err)
	}
	m := linuxMachines[0].(*machines.VirshMachine)

	// Figure out our exact server version
	dclient, err := m.GetEngineAPI()
	if err != nil {
		log.Fatalf("Failure: %s", err)
	}
	ver, err := dclient.ServerVersion(context.Background())
	if err != nil {
		log.Fatalf("Failure: %s", err)
	}
	versionString := ver.Version

	// When layering the disks it seems SELinux gets angry
	out, err := m.MachineSSH("sudo touch /.autorelabel")
	if err != nil {
		log.Fatalf("Failure: %s: %s", err, out)
	}

	// Make sure to nuke the key.json file so it'll be regenerated
	// otherwise older versions of classic swarm freak out due to
	// duplicate engine IDs
	out, err = m.MachineSSH("sudo rm /etc/docker/key.json")
	if err != nil {
		log.Fatalf("Failure: %s: %s", err, out)
	}

	baseDisk := m.BaseDisk
	diskFile := m.DiskPath
	// Immediately delete it, but preserve the disk, then rename the disk
	err = m.RemoveAndPreserveDisk()
	if err != nil {
		log.Fatalf("Failure: %s", err)
	}

	i := strings.LastIndex(baseDisk, ".")
	newName := fmt.Sprintf("%s-%s%s", baseDisk[:i], versionString, baseDisk[i:])
	log.Infof("Renaming %s -> %s", diskFile, newName)
	os.Rename(diskFile, newName)
}
