.PHONY: build install test docs fmt lint

HOSTNAME=registry.terraform.io
NAMESPACE=Mourad-Soltani
NAME=aca
BINARY=terraform-provider-${NAME}
VERSION=1.0.0
OS_ARCH=darwin_amd64

build:
	go build -o ${BINARY}

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}/

test:
	go test -v ./...

fmt:
	go fmt ./...

lint:
	golangci-lint run

docs:
	tfplugindocs generate

clean:
	rm -f ${BINARY}
