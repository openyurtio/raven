/*
 * Copyright 2022 The OpenYurt Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package network_engine

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/vdobler/ht/errorlist"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/pkg/types"
)

const (
	SecretFile string = "/etc/ipsec.d/raven.secrets"
	DefaultPSK string = "openyurt-raven"
)

type libreswanGateway struct {
	localIP       net.IP
	localPublicIP net.IP
	localSubnets  []string
	connections   map[string]map[string]string
	central       bool
}

func (l *libreswanGateway) Init(localIP net.IP, localGatewayPublicIP net.IP) {
	l.localIP = localIP
	l.localPublicIP = localGatewayPublicIP
}

func (l *libreswanGateway) Start() {
	l.connections = make(map[string]map[string]string)

	// Ensure secrets file
	_, err := os.Stat(SecretFile)
	if err == nil {
		os.Remove(SecretFile)
	}
	file, err := os.Create(SecretFile)
	if err != nil {
		klog.Errorf("fail to create secrets file: %v", err)
	}
	defer file.Close()

	psk := os.Getenv("LIBRESWAN_PSK")
	if psk == "" {
		psk = DefaultPSK
		klog.Warning(fmt.Sprintf("use weak PSK: %s", psk))
	}
	fmt.Fprintf(file, "%%any %%any : PSK \"%s\"\n", psk)

	// Run pluto
	if err := l.runPluto(); err != nil {
		klog.Error(err)
	}
}

// UpdateLocalEndpoint Update Endpoint Configuration on Local Config/Subnet Changed
func (l *libreswanGateway) UpdateLocalEndpoint(local *types.Endpoint) {
	l.localSubnets = local.Subnets
	if l.central != local.Central {
		l.Cleanup()
		l.central = local.Central
	}
}

func (l *libreswanGateway) EnsureEndpoints(gateways map[string]*types.Endpoint) {
	// ensure expect active connection id
	expect := make(map[string]string)
	for _, ep := range gateways {
		id := fmt.Sprintf("%s-%s-%v-%v", ep.ID, ep.Vtep, l.localIP, l.localPublicIP)
		expect[id] = ep.ID
	}

	// delete useless vpn connections
	for id, conn := range l.connections {
		if _, ok := expect[id]; !ok {
			for c := range conn {
				if err := l.whackDelConnection(c); err != nil {
					klog.ErrorS(err, "fail to delete connection", "connection", c)
				}
			}
			delete(l.connections, id)
		}
	}
}

func (l *libreswanGateway) whackConnectToEndpoint(connectionName string, gateway *types.Endpoint, localSubnet, remoteSubnet string) error {
	args := make([]string, 0)
	args = append(args, "--psk", "--encrypt", "--forceencaps", "--name", connectionName,
		// local
		"--id", l.localIP.String(),
		"--host", l.localIP.String(),
		"--client", localSubnet,
		"--ikeport", "4500",

		"--to",

		// remote
		"--id", gateway.ID,
		"--host", gateway.Vtep.String(),
		"--client", remoteSubnet,
		"--ikeport", "4500")

	if err := l.whackCmd(args...); err != nil {
		return err
	}
	if !l.central {
		if err := l.whackCmd("--route", "--name", connectionName); err != nil {
			return err
		}
		if err := l.whackCmd("--initiate", "--asynchronous", "--name", connectionName); err != nil {
			return err
		}
	}
	return nil
}

func (l *libreswanGateway) ConnectToEndpoint(gateway *types.Endpoint) error {
	// Ensure ipsec connections
	id := fmt.Sprintf("%s-%s-%v-%v", gateway.ID, gateway.Vtep, l.localIP, l.localPublicIP)
	existing := l.connections[id]
	expect := l.genConnectionName(gateway)

	connections := make(map[string]string)
	errList := errorlist.List{}
del:
	for conn, subnets := range existing {
		if _, exist := expect[conn]; exist {
			connections[conn] = subnets
			continue del
		}
		if err := l.whackDelConnection(conn); err != nil {
			connections[conn] = subnets
			errList = errList.Append(fmt.Errorf("fail to delete connection (%v): %v", conn, err))
		}
	}
add:
	for conn, subnets := range expect {
		_, exist := existing[conn]
		if exist {
			continue add
		}
		subnet := strings.Split(subnets, "-")
		if err := l.whackConnectToEndpoint(conn, gateway, subnet[0], subnet[1]); err != nil {
			errList = errList.Append(fmt.Errorf("fail to delete connection (%v): %v", conn, err))
		} else {
			connections[conn] = subnets
		}
	}
	l.connections[id] = connections
	return errList.AsError()
}

func (l *libreswanGateway) whackCmd(args ...string) error {
	var err error
	var output []byte
	for i := 0; i < 5; i++ {
		cmd := exec.Command("/usr/libexec/ipsec/whack", args...)
		output, err = cmd.CombinedOutput()
		if err == nil {
			klog.InfoS("whacking with", "args", args, "output", string(output))
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("error whacking with %v: %v", args, err)
	}
	return nil
}

func (l *libreswanGateway) genConnectionName(gateway *types.Endpoint) map[string]string {
	connections := make(map[string]string)
	for _, localSubnet := range l.localSubnets {
		for _, remoteSubnet := range gateway.Subnets {
			connectionName := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%s-%s", l.localIP, gateway.ID, localSubnet, remoteSubnet))))
			connections[connectionName] = fmt.Sprintf("%s-%s", localSubnet, remoteSubnet)
		}
	}
	return connections
}

func (l *libreswanGateway) whackDelConnection(conn string) error {
	return l.whackCmd("--delete", "--name", conn)
}

func (l *libreswanGateway) Cleanup() {
	for _, conn := range l.connections {
		for c := range conn {
			if err := l.whackDelConnection(c); err != nil {
				klog.ErrorS(err, "fail to delete connection", "connection", c)
			}
		}
	}
	l.connections = make(map[string]map[string]string)

	_, err := exec.Command("bash", "-c", "/sbin/ip xfrm policy flush; /sbin/ip xfrm state flush; true").CombinedOutput()
	if err != nil {
		klog.ErrorS(err, "error clean up xfrm policy and state")
	}
}

func (l *libreswanGateway) runPluto() error {
	klog.Info("starting pluto")

	cmd := exec.Command("/usr/local/bin/pluto")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("error start pluto: %v", err)
	}

	go func() {
		klog.Fatalf("pluto exited: %v", cmd.Wait())
	}()

	for i := 0; i < 5; i++ {
		_, err = os.Stat("/run/pluto/pluto.ctl")
		if err == nil {
			klog.Info("start pluto successfully")
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("failed to stat the control socket: %v", err)
	}
	return nil
}
