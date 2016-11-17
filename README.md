# docker-e2e #
`docker-e2e` is a project to end-to-end test Docker Engine, especially 
orchestration features, in real deployment environments. Unlike integration 
tests, the goal of `docker-e2e` is to issue commands strictly through public 
apis to real Docker Engines running real containers. 


## Overview ##
The tests are built with the `go test` framework, and in some circumstances, 
simply running `go test ./tests` in the project root will run the tests, 
possibly successfully. The tests are designed to be run on a real, multi-node 
cluster so their functionality, utility, and accuracy are reduced in a 
single-node environment. However, a cluster of 1 node is a valid cluster, and 
most tests should run successfully in a 1 node cluster. The tests will not work 
if swarm mode is not enabled.

To facilitate running tests on real clusters, the `testkit` tool has been 
created. `testkit` contains some simple commands for spinning up and managing
clusters as well as running tests. 

The tests are designed to be run inside of a docker container, which should be
started with `--net=host` and the docker socket bind-mounted into the container
at `/var/run/docker.sock`. This container should be run on a Manager node, or
the API calls related to cluster management will all fail.

The tests must be run on a Docker Swarm Mode manager node.

## Development Workflow ##

Before you start working, make sure you have a development cluster ready to go.
If you're using `testkit`, you can do `testkit create --name somename <cfg>` 
with a config file to provision an environment on AWS. You can choose not to 
pass name, but if you do your cluster will have gooblydegock for a name. 

Then, you can get started developing your tests. There isn't a hard and fast
framework for building tests; just write code that expresses what you need to 
do to adequately express your test case. Testing is relatively black-box, so 
you should restrain yourself to only using the official docker go client.

When you're ready to try out your tests, you should set up a forwarded socket 
to connect your local docker client to the cluster you provisioned earlier. You
can do this by doing `testkit attach somename`. This will open `docker.sock` in
the local directory. 

Next, open another terminal and `export DOCKER_HOST=unix://$(pwd)/docker.sock` 
to tell your docker client to connect to this socket. This socket is forwarded 
over SSH to the docker socket on the remote cluster. Do `docker info` to make 
sure you've connected your docker client to the remote cluster.

Finally, you're ready to build and run the tests. Do: 

```
$ docker build -t e2e .
$ docker run --net=host -v /var/run/docker.sock:/var/run/docker.sock
```

This first builds and then runs the tests on the remote cluster. If you need
and ssh connection to the remote cluster to debug something, you can do 
`testkit ssh somename` to get an IP address that you can use as an SSH 
endpoint. When you're done with your cluster, you should do 
`testkit rm somename` to delete it.

Running the Tests with Testkit
------------------------------

`cd testkit`
`go get -v ./...`
`brew install awscli`

