docker-e2e
==========
`docker-e2e` is a project to end-to-end test Docker Engine, especially 
orchestration features, in real deployment environments. Unlike integration 
tests, the goal of `docker-e2e` is to issue commands strictly through public 
apis to real Docker Engines running real containers. 

Building the Tests
------------------
The tests require go version 1.7+

To compile the tests to a static binary, use `go test -c`.

To build a docker image with the

Running the Tests
-----------------
Tests are built with the go test framework, and as such, running `go test ./tests` in 
the project root will run the tests. 

Alternatively, tests can be run in a docker container. You will have to mount
`/var/run/docker.sock` into the container, as well as supplying an ip address
that the container can hit to check network functionality. The endpoint is
passed as an environment variable, `DOCKER_E2E_ENDPOINT`. 

The full invokation looks like:
```
docker run -v /var/run/docker.sock:/var/run/docker.sock -e DOCKER_E2E_ENDPOINT=123.45.67.8 dockerswarm/e2e
```

The tests must be run on a Docker Swarm Mode manager node.

Running the Tests with Testkit
------------------------------

`cd tesetkit`
`go get -v ./...`
`brew install awscli`

