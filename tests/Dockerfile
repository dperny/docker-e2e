FROM golang:1.7-alpine

RUN apk add --update \
		git \
		&& rm -rf /var/cache/apk/*
RUN mkdir -p /go/src/github.com/docker/docker-e2e/tests
WORKDIR /go/src/github.com/docker/docker-e2e/tests

COPY . /go/src/github.com/docker/docker-e2e/tests
RUN go get -v -d -t ./...
RUN go test -c

CMD ["/go/src/github.com/docker/docker-e2e/tests/tests.test", "-test.v"]
