# Build the manager binary
FROM golang:1.18 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY pkg/ pkg/
COPY cmd/ cmd/

ARG TARGETOS
ARG TARGETARCH
ARG GITCOMMIT

# Build
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GO111MODULE=on go build -ldflags "-X main.GitCommit=${GITCOMMIT}" -a -o raven-agent-ds cmd/agent/main.go


FROM alpine:3.18
COPY hack/iptables-wrapper-installer.sh /iptables-wrapper-installer.sh
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add openrc libreswan libreswan-openrc ipset iptables python3 wireguard-tools nftables bash --no-cache \
    && /iptables-wrapper-installer.sh --no-sanity-check \
    && sed -i 's/runscript/openrc-run/g' /etc/init.d/ipsec \
    && sed -i 's/#logfile=/logfile=/g' /etc/ipsec.conf \
    && mkdir -p /run/openrc \
    && mkdir -p /run/pluto \
    && touch /run/openrc/softlevel \
    && rc-update add ipsec

COPY --from=builder /workspace/raven-agent-ds /usr/local/bin/
COPY pluto /usr/local/bin/

ENTRYPOINT  ["/usr/local/bin/raven-agent-ds"]