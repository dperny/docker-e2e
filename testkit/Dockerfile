FROM golang:1.7-alpine

RUN apk add --update \
		git \
                libvirt-client \
                qemu-img \
                openssh-client \
		&& rm -rf /var/cache/apk/*
RUN mkdir -p /go/src/github.com/docker/docker-e2e/testkit && \
	mkdir -p /root/.ssh
WORKDIR /go/src/github.com/docker/docker-e2e/testkit

COPY . /go/src/github.com/docker/docker-e2e/testkit
RUN go get -v -d ./... && \
	go install -v && \
	go install -v ./machines/build_machines && \
	go install -v ./machines/virsh_inject_engine

ENTRYPOINT ["testkit"]
