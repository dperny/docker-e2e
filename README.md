# docker-e2e
`docker-e2e` is a project to end-to-end test Docker Engine, especially 
orchestration features, in real deployment environments. Unlike integration 
tests, the goal of `docker-e2e` is to issue commands strictly through public 
apis to real Docker Engines running real containers. 


## Overview
The tests are built with the `go test` framework, but are most easily run from
inside of a container. The tests are run with `--net=host` and the docker 
socket bind-mounted into the container at `/var/run/docker.sock`. This 
container is run on a Manager node.

The tests are designed to be run on a real, multi-node cluster so their 
functionality, utility, and accuracy are reduced in a single-node environment. 
However, a cluster of 1 node is a valid cluster, and tests should run 
successfully in a 1 node cluster. The tests will not work if swarm mode is not 
enabled.

To facilitate running tests on real clusters, the `testkit` tool has been 
created. `testkit` contains some simple commands for spinning up and managing
clusters as well as running tests. 

## Development Workflow

Before you start working, make sure you have a development cluster ready to go.
You can provision a cluster in the environment of your choice, or you can use
testkit to have one provisioned on AWS for you.

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

If you are not using testkit, you can set this socket up manually, or you can 
simply ssh into the machine and copy over your working code. 

Finally, you're ready to build and run the tests. Do: 

```
$ docker build -t e2e .
$ docker run --net=host -v /var/run/docker.sock:/var/run/docker.sock e2e
```

This first builds and then runs the tests on the remote cluster. If you need
and ssh connection to the remote cluster to debug something, you can do 
`testkit ssh somename` to get an IP address that you can use as an SSH 
endpoint. When you're done with your cluster, you should do 
`testkit rm somename` to delete it.

