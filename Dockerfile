# Build the manager binary
FROM golang:1.17 as builder

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

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o agent cmd/agent/main.go


FROM alpine:3.15
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add openrc libreswan libreswan-openrc iptables python3 bash --no-cache \
    && sed -i 's/runscript/openrc-run/g' /etc/init.d/ipsec \
    && sed -i 's/#logfile=/logfile=/g' /etc/ipsec.conf \
    && mkdir -p /run/openrc \
    && mkdir -p /run/pluto \
    && touch /run/openrc/softlevel \
    && rc-update add ipsec

COPY --from=builder /workspace/agent /usr/local/bin/
COPY pluto raven.sh /usr/local/bin/

ENTRYPOINT raven.sh