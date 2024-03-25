GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	go build -o vault/plugins/grafana-cloud cmd/grafana-cloud/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault secrets enable -path=grafana-cloud grafana-cloud

clean:
	rm -f ./vault/plugins/grafana-cloud

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
