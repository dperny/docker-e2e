# Machine Management

This directory contains libraries and utility CLIs for creating
test machines.

## Supported Back-ends

* docker-machine (KVM, AWS, virtualbox, etc.)
* native virsh
* **WIP:** native virtualbox
* **WIP:** native aws

Generally the native back-ends provide better support for various
enterprise Linux distros and the docker-machine back-end will likely be
deprecated and ultimately removed once we have fleshed out the native
back-ends.


## Base Images

To best utilise the native back-ends, one or more pre-installed and
pre-configured base images are generated and stored in an S3 bucket so
they can be quickly and easily replicated locally to run tests.

Due to licensing restrictions on most enterprise linux distributions,
these can not be made directly available, however our goal is to publish
a set of freely redistributable images on a public S3 bucket soon.

For Docker employees who are members of the `dockerinc` AWS org, the images
can be replicated with:

```
aws s3 sync s3://e2e-images/ /e2e
```


## Virsh

Once you have replicated the images, you can deploy one or more machines.

(replace the XXX's below as applicable for your target OS image and engine version)


```
export MACHINE_DRIVER=virsh
export VIRSH_OS_LINUX=XXX
export VIRSH_OS_WINDOWS=XXX
export ENGINE_INSTALL_CMD=XXX
export ENGINE_INSTALL_WIN_URL=XXX

docker run --rm -it --entrypoint build_machines \
    -e VIRSH_DISK_DIR=/e2e \
    -e VIRSH_OS \
    -e MACHINE_DRIVER \
    -e ENGINE_INSTALL_CMD \
    -e ENGINE_INSTALL_URL \
    -v /e2e:/e2e \
    -v /var/run/libvirt:/var/run/libvirt \
    dockerswarm/testkit:latest 1 1
```
