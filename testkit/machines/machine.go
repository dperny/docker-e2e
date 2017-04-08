package machines

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

var (
	// NamePrefix denotes the machine prefix for the test.
	NamePrefix = os.Getenv("MACHINE_PREFIX") + "E2E"
	// Timeout denotes the timeout on the docker client.
	Timeout = 180 * time.Second
	// BusyboxImage denotes the busybox image string.
	BusyboxImage = "busybox"
	// ErrPathDoesNotExist denotes whether the path specified exists on the build host.
	ErrPathDoesNotExist = errors.New("The specified path does not exist on the host")
	// RetryCount denotes the amount of times retries happen.
	RetryCount = 3
)

// Machine Interface for test machine management
type Machine interface {
	GetName() string
	GetDockerHost() string
	GetEngineAPI() (*client.Client, error)
	GetEngineAPIWithTimeout(timeout time.Duration) (*client.Client, error)
	Remove() error
	Stop() error
	Start() error
	GetIP() (string, error)
	GetInternalIP() (string, error)
	CatHostFile(hostPath string) ([]byte, error)
	TarHostDir(hostPath string) ([]byte, error)
	MachineSSH(command string) (string, error)
	GetConnectionEnv() string
	WriteFile(filepath string, data io.Reader) error
	IsWindows() bool
}

// Environment is a simple wrapper around a set of related machines
type Environment struct {
	StackName string
	Machines  []Machine
}

// GetTestMachines uses docker-machine to create a test engine which can then be used for integration tests (try RetryCount times)
func GetTestMachines(linuxCount, windowsCount int) ([]Machine, []Machine, error) {
	return GetTestMachinesWithDockerRootDir(linuxCount, windowsCount, "")
}

// GetTestMachinesWithDockerRootDir generates linux and windows machines in parallel
// returning an array of linux machines, windows machines, and any error
func GetTestMachinesWithDockerRootDir(linuxCount int, windowsCount int, dockerRootDir string) ([]Machine, []Machine, error) {
	if os.Getenv("MACHINE_DRIVER") == "virsh" {
		return NewVirshMachines(linuxCount, windowsCount) // TODO dockerRootDir
	}
	return NewBuildMachines(linuxCount, windowsCount, dockerRootDir)
}

func ListEnvironments() ([]*Environment, error) {
	if os.Getenv("MACHINE_DRIVER") == "virsh" {
		return VirshListEnvironments()
	}
	return DockerMachineListEnvironments()
}

func DestroyEnvironment(name string) error {
	if os.Getenv("MACHINE_DRIVER") == "virsh" {
		return VirshDestroyEnvironment(name)
	}
	return DockerMachineDestroyEnvironment(name)
}

// HostDirManifest Return a manifest of the files on the host in the directory (using find $hostpath)
func HostDirManifest(m Machine, hostPath string) (map[string]interface{}, error) {
	cmd := []string{"sh", "-c", "cd /theDir && find . -print"}
	binds := []string{fmt.Sprintf("%s:/theDir:ro", hostPath)}
	log.Debug("Running find")
	data, err := RunCommand(m, BusyboxImage, cmd, binds, []string{})
	if err != nil {
		log.Debugf("failed: %s", err)
		return nil, err
	}
	res := make(map[string]interface{})
	for _, line := range strings.Split(string(data), "\n") {
		log.Debug(line)
		res[line] = struct{}{}
	}
	return res, nil
}

// Get the contents of a specific file on the engine
func CatHostFile(m Machine, hostPath string) ([]byte, error) {
	cmd := []string{"cat", "/thefile"}
	binds := []string{fmt.Sprintf("%s:/thefile:ro", hostPath)}
	return RunCommand(m, BusyboxImage, cmd, binds, []string{})
}

// CatHostFileOnVolume Get the contents of a specific file in a volume
func CatHostFileOnVolume(m Machine, volname, path string) ([]byte, error) {
	cmd := []string{"cat", "/volume_mount_dir/" + path}
	binds := []string{fmt.Sprintf("%s:/volume_mount_dir:ro", volname)}
	return RunCommand(m, BusyboxImage, cmd, binds, []string{})
}

// GetHostFileUIDOnVolume Get the host file UID in a volume
func GetHostFileUIDOnVolume(m Machine, volname, path string) (string, error) {
	cmd := []string{"stat", "-c", "%u", "/volume_mount_dir/" + path}
	binds := []string{fmt.Sprintf("%s:/volume_mount_dir:ro", volname)}
	out, err := RunCommand(m, BusyboxImage, cmd, binds, []string{})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Get the content of a directory as a tar file from the engine
func TarHostDir(m Machine, hostPath string) ([]byte, error) {
	// TODO - Might want to consider compression if we find we're transfering significant data during tests
	cmd := []string{"tar", "--directory", "/theDir", "-cf", "-", "."}
	binds := []string{fmt.Sprintf("%s:/theDir:ro", hostPath)}
	return RunCommand(m, BusyboxImage, cmd, binds, []string{})
}

func RunCommand(m Machine, image string, cmd, binds, entrypoint []string) ([]byte, error) {
	log.Debugf("Running - image:%s entrypoint:%s cmd:%s binds:%s", image, entrypoint, cmd, binds)
	c, err := m.GetEngineAPI()
	if err != nil {
		return nil, err
	}
	_, _, errI := c.ImageInspectWithRaw(context.TODO(), image)
	if errI != nil {
		log.Infof("Pulling %s", image)
		// Use a very large timeout so that we don't time out while
		// reading the response body.
		pullClient, errP := m.GetEngineAPIWithTimeout(300 * time.Second)
		if errP != nil {
			return nil, fmt.Errorf("Failed to get engine api with timeout %s: %s", 300*time.Second, errP)
		}
		r, errPC := pullClient.ImagePull(context.TODO(), image, types.ImagePullOptions{})
		if errPC != nil {
			return nil, fmt.Errorf("Failed to pull %s: %s", image, errPC)
		}
		_, err = ioutil.ReadAll(r)
		r.Close()
		if err != nil {
			return nil, fmt.Errorf("Failed to pull %s: %s", image, err)
		}
	}

	cfg := &container.Config{
		Image:        image,
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmd,
	}
	if len(entrypoint) > 0 {
		cfg.Entrypoint = entrypoint
	}
	hostConfig := &container.HostConfig{Binds: binds}

	resp, err := c.ContainerCreate(context.TODO(), cfg, hostConfig, nil, "")
	if err != nil {
		return nil, fmt.Errorf("Failed to create container %s", err)
	}
	containerID := resp.ID
	defer c.ContainerRemove(context.TODO(), containerID, types.ContainerRemoveOptions{})

	attachResp, err := c.ContainerAttach(context.TODO(), containerID, types.ContainerAttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return nil, err
	}
	reader := attachResp.Reader

	errC := c.ContainerStart(context.TODO(), containerID, types.ContainerStartOptions{})
	if errC != nil {
		log.Debugf("Failed to launch inspection container: %s", err)
		return nil, errC
	}
	timeout := 5 * time.Second
	defer c.ContainerStop(context.TODO(), containerID, &timeout)

	stdoutBuffer := new(bytes.Buffer)
	stderrBuffer := new(bytes.Buffer)

	// stdCopy is really chatty in debug mode
	oldLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	defer log.SetLevel(oldLevel)
	if _, err = stdcopy.StdCopy(stdoutBuffer, stderrBuffer, reader); err != nil {
		log.Info("cannot read logs from logs reader")
		return nil, err
	}
	stderr := stderrBuffer.String()
	if strings.Contains(strings.ToLower(stderr), "no such file") {
		// XXX This doesn't seem to hit...
		log.Info("Got a no such file on stderr")
		log.Info(stderr)
		return nil, ErrPathDoesNotExist
	}

	info, err := c.ContainerInspect(context.TODO(), containerID)
	if err != nil {
		return nil, fmt.Errorf("Failed to inspect container after completion: %s", err)
	}
	if info.State == nil {
		return nil, fmt.Errorf("Container didn't finish")
	}

	if info.State.ExitCode != 0 {
		// return nil, fmt.Errorf("Container exited with %d", info.State.ExitCode)
		// XXX We'll assume an error is the path didn't exist, not some other random glitch.
		//     Not ideal, but the log output doesn't seem to contain the "no such file"
		//     as expected.
		log.Info("Non zero exit code: %d", info.State.ExitCode)
		return nil, ErrPathDoesNotExist
	}

	// Looks like it worked OK
	return stdoutBuffer.Bytes(), nil
}

// VolumeExists Check if a given volume exists
func VolumeExists(client *client.Client, name string) bool {
	_, err := client.VolumeInspect(context.TODO(), name)
	return err == nil
}

// LoadFileInVolume Load a file in the given volume
func LoadFileInVolume(client *client.Client, volname, filename, contents string) error {
	if !VolumeExists(client, volname) {
		if _, err := client.VolumeCreate(context.TODO(), volume.VolumesCreateBody{
			Name: volname,
		}); err != nil {
			return err
		}
	}

	cfg := &container.Config{
		Image: "busybox",
		Cmd: strslice.StrSlice([]string{
			"sh", "-c",
			fmt.Sprintf("mkdir -p $(dirname /data/%s); cat - > /data/%s", filename, filename),
		}),
		OpenStdin:   true,
		AttachStdin: true,
		StdinOnce:   true,
	}
	hostConfig := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:/data", volname),
		},
	}

	resp, err := client.ContainerCreate(context.TODO(), cfg, hostConfig, nil, "")
	if err != nil {
		log.Fatal(err)
	}
	containerID := resp.ID
	defer client.ContainerRemove(context.TODO(), containerID, types.ContainerRemoveOptions{})

	errCS := client.ContainerStart(context.TODO(), containerID, types.ContainerStartOptions{})
	if errCS != nil {
		return fmt.Errorf("Failed to launch container to load data to volume: %s", errCS)
	}
	timeout := 5 * time.Second
	defer client.ContainerStop(context.TODO(), containerID, &timeout)

	attachResp, err := client.ContainerAttach(context.TODO(), containerID, types.ContainerAttachOptions{
		Stream: true,
		Stdin:  true,
	})
	if err != nil {
		return fmt.Errorf("Failed to attach to container to load data to volume: %s", err)
	}
	defer attachResp.Close()
	if _, err := io.Copy(attachResp.Conn, strings.NewReader(contents)); err != nil {
		return fmt.Errorf("input copy interrupted: %s", err)
	}
	log.Debugf("Created file %s on volume %s", filename, volname)
	return nil
}

// LoadFileInHost Load file in the host
func LoadFileInHost(client *client.Client, filename, contents string) error {
	dir := filepath.Dir(filename)

	cfg := &container.Config{
		Image: "busybox",
		Cmd: strslice.StrSlice([]string{
			"sh", "-c",
			fmt.Sprintf("cat - > %s", filename),
		}),
		OpenStdin:   true,
		AttachStdin: true,
		StdinOnce:   true,
	}
	hostConfig := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:%s", dir, dir),
		},
	}

	resp, err := client.ContainerCreate(context.TODO(), cfg, hostConfig, nil, "")
	if err != nil {
		log.Fatal(err)
	}
	containerID := resp.ID
	defer client.ContainerRemove(context.TODO(), containerID, types.ContainerRemoveOptions{})

	errCS := client.ContainerStart(context.TODO(), containerID, types.ContainerStartOptions{})
	if errCS != nil {
		return fmt.Errorf("Failed to launch container to load data to host: %s", errCS)
	}
	timeout := 5 * time.Second
	defer client.ContainerStop(context.TODO(), containerID, &timeout)

	attachResp, err := client.ContainerAttach(context.TODO(), containerID, types.ContainerAttachOptions{
		Stream: true,
		Stdin:  true,
	})
	if err != nil {
		return fmt.Errorf("Failed to attach to container to load data to host: %s", err)
	}
	defer attachResp.Close()
	if _, err := io.Copy(attachResp.Conn, strings.NewReader(contents)); err != nil {
		return fmt.Errorf("input copy interrupted: %s", err)
	}
	log.Debugf("Created file %s on host", filename)
	return nil
}
