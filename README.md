# docker-e2e
`docker-e2e` is a project to end-to-end test Docker Engine, especially 
orchestration features, in real deployment environments. Unlike integration 
tests, the goal of `docker-e2e` is to issue commands strictly through public 
apis to real Docker Engines running real containers. 


## Overview
The tests are built with the `go test` framework, but are most easily run from
inside of a container. The docker socket bind-mounted into the container at
`/var/run/docker.sock`. This container is run on a Manager node.

The tests are designed to be run on a real, multi-node cluster so their 
functionality, utility, and accuracy are reduced in a single-node environment. 
However, a cluster of 1 node is a valid cluster, and tests should run 
successfully in a 1 node cluster. The tests will not work if swarm mode is not 
enabled.

To facilitate running tests on real clusters, the `testkit` tool has been 
created. `testkit` contains some simple commands for spinning up and managing
clusters as well as running tests. 

## Using testkit

### Setup AWS credentials

```
$ brew install awscli  # or equivalent
$ aws configure
```

### Build or install testkit

```
$ go get github.com/docker/docker-e2e/testkit
```

### Define an environment

Use https://github.com/docker/docker-e2e/blob/master/testkit/e2e.yml as an example.

Make sure to set `ssh_keyname` to a valid AWS SSH key (and save the private key in `~/.ssh`)

### Run the tests

You can use testkit in a few different ways:

- `testkit create --name foo myenv.yml` will create the environment, and that's it
- `testkit exec myenv.yml foo` will execute the test commands defined in the configuration in a given environment
- `testkit run --name foo myenv.yml` will do both a *create* and *exec*

### Manage Environments

In order to manage those environments, *testkit* provides a few commands
such as `testkit ls` and `testkit rm`.

`testkit` can also *purge* old test environments (to avoid leaking):
```
$ testkit purge --ttl=1h
```

### Development

*testkit* provides a few helpers for development.

You can directly ssh into a test environment by running `testkit ssh`.

`testkit attach` creates a local Docker socket and proxies the call to the remote environment:
```
testkit create --name foo e2e.yml
testkit attach foo
export DOCKER_HOST=unix://$(pwd)/docker.sock
```

### Running test locally

```
$ testkit create --name myenv e2e.yml
$ testkit attach myenv
[do some test changes]
$ docker build -t e2e .
$ docker run -v /var/run/docker.sock:/var/run/docker.sock e2e
```

## Testkit Machines management

The `./testkit/machines` tree contains low-level machine provisioning logic
that can be used to rapidly spin up test machines.

For more detais, see [./testkit/machines/README.md](./testkit/machines/README.md)
