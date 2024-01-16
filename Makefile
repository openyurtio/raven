
# Image URL to use all building/pushing image targets
IMG ?= openyurt/raven-agent:latest
VPN_DRIVER ?= libreswan
FORWARD_NODE_IP ?= false
NAT_TRAVERSAL ?= false
METRIC_BIND_ADDR ?= ":8080"

BUILDPLATFORM ?= linux/amd64
TARGETOS ?= linux
TARGETARCH ?= amd64

GITCOMMIT = $(shell git rev-parse HEAD)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

##@ Build

build: fmt vet ## Build agent binary.
	go build -o bin/agent cmd/agent/main.go

run: fmt vet ## Run a controller from your host.
	go run cmd/agent/main.go

docker-build:## Build docker image with the agent.
	docker build --platform=${BUILDPLATFORM} --build-arg TARGETOS=${TARGETOS} --build-arg TARGETARCH=${TARGETARCH} --build-arg GITCOMMIT=${GITCOMMIT} -t ${IMG} .

docker-push: ## Push docker image with the agent.
	docker push ${IMG}

##@ Deploy

gen-deploy-yaml:
	bash hack/gen-yaml.sh ${IMG} ${VPN_DRIVER} ${FORWARD_NODE_IP} ${METRIC_BIND_ADDR} ${NAT_TRAVERSAL}

deploy: gen-deploy-yaml ## Deploy agent daemon.
	kubectl apply -f _output/yamls/raven-agent.yaml

undeploy:
	kubectl delete -f _output/yamls/raven-agent.yaml

.PHONY: deploy gen-deploy-yaml undeploy

