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

package libreswan

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/vdobler/ht/errorlist"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	iptablesutil "github.com/openyurtio/raven/pkg/networkengine/util/iptables"
	netlinkutil "github.com/openyurtio/raven/pkg/networkengine/util/netlink"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/openyurtio/raven/pkg/utils"
)

const (
	IPSecEncapLen = 64

	// DriverName specifies name of libreswan VPN backend driver.
	DriverName = "libreswan"
)

var _ vpndriver.Driver = (*libreswan)(nil)

// can be modified for testing.
var whackCmd = whackCmdFn
var findCentralGw = vpndriver.FindCentralGwFn
var enableCreateEdgeConnection = vpndriver.EnableCreateEdgeConnection

func init() {
	vpndriver.RegisterDriver(DriverName, New)
}

const (
	SecretFile string = "/etc/ipsec.d/raven.secrets"
)

type libreswan struct {
	relayConnections  map[string]*vpndriver.Connection
	edgeConnections   map[string]*vpndriver.Connection
	nodeName          types.NodeName
	centralGw         *types.Endpoint
	iptables          iptablesutil.IPTablesInterface
	listenPort        string
	keepaliveInterval int
	keepaliveTimeout  int
}

func (l *libreswan) Init() (err error) {
	l.iptables, err = iptablesutil.New()
	if err != nil {
		return err
	}
	// Ensure secrets file
	_, err = os.Stat(SecretFile)
	if err == nil {
		if err := os.Remove(SecretFile); err != nil {
			return err
		}
	}
	file, err := os.Create(SecretFile)
	if err != nil {
		klog.Errorf("fail to create secrets file: %v", err)
		return err
	}
	defer file.Close()

	psk := vpndriver.GetPSK()
	fmt.Fprintf(file, "%%any %%any : PSK \"%s\"\n", psk)

	return l.runPluto()
}

func New(cfg *config.Config) (vpndriver.Driver, error) {
	return &libreswan{
		relayConnections:  make(map[string]*vpndriver.Connection),
		edgeConnections:   make(map[string]*vpndriver.Connection),
		nodeName:          types.NodeName(cfg.NodeName),
		listenPort:        cfg.Tunnel.VPNPort,
		keepaliveInterval: cfg.Tunnel.KeepAliveInterval,
		keepaliveTimeout:  cfg.Tunnel.KeepAliveTimeout,
	}, nil
}

func (l *libreswan) Apply(network *types.Network, routeDriverMTUFn func(*types.Network) (int, error)) (err error) {
	if network.LocalEndpoint == nil || len(network.RemoteEndpoints) == 0 {
		klog.Info("no local gateway or remote gateway is found, cleaning vpn connections")
		return l.Cleanup()
	}
	if network.LocalEndpoint.NodeName != l.nodeName {
		klog.Infof(utils.FormatTunnel("the current node is not gateway node, cleaning vpn connections"))
		return l.Cleanup()
	}

	if err := l.createConnections(network); err != nil {
		return fmt.Errorf("error create VPN tunnels: %v", err)
	}

	return nil
}

func (l *libreswan) MTU() (int, error) {
	mtu, err := vpndriver.DefaultMTU()
	if err != nil {
		return 0, err
	}
	return mtu - IPSecEncapLen, nil
}

// getEndpointResolver returns a function that resolve the left subnets and the Endpoint that should connect to.
func (l *libreswan) getEndpointResolver(network *types.Network) func(centralGw, remoteGw *types.Endpoint) (leftSubnets []string, connectTo *types.Endpoint) {
	snUnderNAT := make(map[types.GatewayName]*types.Endpoint)
	for _, v := range network.RemoteEndpoints {
		if v.UnderNAT {
			snUnderNAT[v.GatewayName] = v
		}
	}
	return func(centralGw, remoteGw *types.Endpoint) (leftSubnets []string, connectTo *types.Endpoint) {
		leftSubnets = network.LocalEndpoint.Subnets
		if centralGw == nil {
			// If both local and remote gateway are NATed but no central gateway found,
			// we cannot set up vpn connections between the local and remote gateway.
			if network.LocalEndpoint.UnderNAT && remoteGw.UnderNAT {
				return nil, nil
			}
			return leftSubnets, remoteGw
		}

		if centralGw.NodeName == l.nodeName {
			if remoteGw.UnderNAT {
				// If the local gateway is the central gateway,
				// in order to forward traffic from other NATed gateway to the NATed remoteGw,
				// append all subnets of other NATed gateways into left subnets.
				for gwName, v := range snUnderNAT {
					if gwName != remoteGw.GatewayName {
						if !enableCreateEdgeConnection(v, remoteGw) {
							leftSubnets = append(leftSubnets, v.Subnets...)
						}
					}
				}
			}
			return leftSubnets, remoteGw
		}

		// If both local and remote are NATed, and the local gateway is not the central gateway,
		// and can't create edge to edge tunnel, connects to central gateway to forward traffic.
		if network.LocalEndpoint.UnderNAT && remoteGw.UnderNAT {
			if !enableCreateEdgeConnection(network.LocalEndpoint, remoteGw) {
				return leftSubnets, centralGw
			}
		}

		return leftSubnets, remoteGw
	}
}

func (l *libreswan) createConnections(network *types.Network) error {
	l.centralGw = findCentralGw(network)
	desiredEdgeConns, desiredRelayConns := l.computeDesiredConnections(network)
	if len(desiredEdgeConns) == 0 && len(desiredRelayConns) == 0 {
		klog.Infof(utils.FormatTunnel("no desired connections, cleaning vpn connections"))
		return l.Cleanup()
	}

	klog.Infof(utils.FormatTunnel("desired edge connections: %+v, desired relay connections: %+v", desiredEdgeConns, desiredRelayConns))

	if err := l.createEdgeConnections(desiredEdgeConns); err != nil {
		return err
	}
	if err := l.createRelayConnections(desiredRelayConns); err != nil {
		return err
	}

	return nil
}

func (l *libreswan) createEdgeConnections(desiredEdgeConns map[string]*vpndriver.Connection) error {
	if len(desiredEdgeConns) == 0 {
		klog.Infof("no desired edge connections")
		return nil
	}

	errList := errorlist.List{}

	// remove unwanted connections
	for connName := range l.edgeConnections {
		if _, ok := desiredEdgeConns[connName]; !ok {
			err := l.whackDelConnection(connName)
			if err != nil {
				errList = errList.Append(err)
				klog.ErrorS(err, "error disconnecting endpoint", "connectionName", connName)
				continue
			}
			delete(l.edgeConnections, connName)
		}
	}

	// add new connections
	for name, connection := range desiredEdgeConns {
		err := l.connectToEdgeEndpoint(name, connection)
		errList = errList.Append(err)
	}

	return errList.AsError()
}

func (l *libreswan) createRelayConnections(desiredRelayConns map[string]*vpndriver.Connection) error {
	if len(desiredRelayConns) == 0 {
		klog.Infof("no desired relay connections")
		return nil
	}

	errList := errorlist.List{}

	// remove unwanted connections
	for connName := range l.relayConnections {
		if _, ok := desiredRelayConns[connName]; !ok {
			err := l.whackDelConnection(connName)
			if err != nil {
				errList = errList.Append(err)
				klog.ErrorS(err, "error disconnecting endpoint", "connectionName", connName)
				continue
			}
			if l.centralGw.NodeName == l.nodeName {
				errList = errList.Append(l.deleteRavenSkipNAT(l.relayConnections[connName]))
			}
			delete(l.relayConnections, connName)
		}
	}

	// add new connections
	for name, connection := range desiredRelayConns {
		err := l.connectToEndpoint(name, connection)
		errList = errList.Append(err)
		if l.centralGw.NodeName == l.nodeName {
			err = l.ensureRavenSkipNAT(connection)
			errList = errList.Append(err)
		}
	}

	return errList.AsError()
}

func (l *libreswan) ensureRavenSkipNAT(connection *vpndriver.Connection) errorlist.List {
	errList := errorlist.List{}
	for _, subnet := range l.centralGw.Subnets {
		if connection.LocalSubnet == subnet || connection.RemoteSubnet == subnet {
			return errList
		}
	}
	// for raven skip nat
	if err := l.iptables.NewChainIfNotExist(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain); err != nil {
		errList = errList.Append(fmt.Errorf("error create %s chain: %s", iptablesutil.RavenPostRoutingChain, err))
	}
	if err := l.iptables.InsertIfNotExists(iptablesutil.NatTable, iptablesutil.PostRoutingChain, 1, "-m", "comment", "--comment", "raven traffic should skip NAT", "-j", iptablesutil.RavenPostRoutingChain); err != nil {
		errList = errList.Append(fmt.Errorf("error adding chain %s rule: %s", iptablesutil.PostRoutingChain, err))
	}
	if err := l.iptables.AppendIfNotExists(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain, "-s", connection.LocalSubnet, "-d", connection.RemoteSubnet, "-j", "ACCEPT"); err != nil {
		errList = errList.Append(fmt.Errorf("error adding chain %s rule: %s", iptablesutil.RavenPostRoutingChain, err))
	}
	return errList
}

func (l *libreswan) deleteRavenSkipNAT(connection *vpndriver.Connection) errorlist.List {
	errList := errorlist.List{}
	err := l.iptables.NewChainIfNotExist(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain)
	if err != nil {
		errList = errList.Append(fmt.Errorf("error create %s chain: %s", iptablesutil.PostRoutingChain, err))
	}
	for _, subnet := range l.centralGw.Subnets {
		if connection.LocalSubnet == subnet || connection.RemoteSubnet == subnet {
			return errList
		}
	}
	err = l.iptables.DeleteIfExists(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain, "-s", connection.LocalSubnet, "-d", connection.RemoteSubnet, "-j", "ACCEPT")
	if err != nil {
		errList = errList.Append(fmt.Errorf("error deleting %s chain rule: %s", iptablesutil.RavenPostRoutingChain, err))
	}
	return errList
}

func (l *libreswan) computeDesiredConnections(network *types.Network) (map[string]*vpndriver.Connection, map[string]*vpndriver.Connection) {
	desiredEdgeConns := make(map[string]*vpndriver.Connection)
	desiredRelayConns := make(map[string]*vpndriver.Connection)
	resolveEndpoint := l.getEndpointResolver(network)

	leftEndpoint := network.LocalEndpoint
	for _, remoteGw := range network.RemoteEndpoints {
		leftSubnets, connectTo := resolveEndpoint(l.centralGw, remoteGw)
		for _, leftSubnet := range leftSubnets {
			for _, rightSubnet := range remoteGw.Subnets {
				name := connectionName(leftEndpoint.PrivateIP, connectTo.PrivateIP, leftSubnet, rightSubnet)
				connect := &vpndriver.Connection{
					LocalEndpoint:  leftEndpoint.Copy(),
					RemoteEndpoint: connectTo.Copy(),
					LocalSubnet:    leftSubnet,
					RemoteSubnet:   rightSubnet,
				}
				if enableCreateEdgeConnection(leftEndpoint.Copy(), connectTo.Copy()) {
					desiredEdgeConns[name] = connect
				} else {
					desiredRelayConns[name] = connect
				}
			}
		}
	}

	return desiredEdgeConns, desiredRelayConns
}

func (l *libreswan) whackConnectToEndpoint(connectionName string, connection *vpndriver.Connection) error {
	args := make([]string, 0)
	leftID := fmt.Sprintf("@%s-%s-%s", connection.LocalEndpoint.PrivateIP, connection.LocalSubnet, connection.RemoteSubnet)
	rightID := fmt.Sprintf("@%s-%s-%s", connection.RemoteEndpoint.PrivateIP, connection.RemoteSubnet, connection.LocalSubnet)
	//TODO Configure "--forceencaps" only when necessary.
	//  "--forceencaps" is not necessary for endpoints that are not behind NAT device.
	// local
	if !connection.LocalEndpoint.UnderNAT {
		args = append(args, "--psk", "--encrypt", "--forceencaps", "--name", connectionName,
			"--id", leftID,
			"--host", connection.LocalEndpoint.String(),
			"--client", connection.LocalSubnet,
			"--ikeport", l.listenPort,
		)
	} else {
		args = append(args, "--psk", "--encrypt", "--forceencaps", "--name", connectionName,
			"--id", leftID,
			"--host", connection.LocalEndpoint.String(),
			"--client", connection.LocalSubnet,
		)
	}
	// remote
	if !connection.RemoteEndpoint.UnderNAT {
		args = append(args, "--to",
			"--id", rightID,
			"--host", connection.RemoteEndpoint.PublicIP,
			"--client", connection.RemoteSubnet,
			"--ikeport", l.listenPort)
	} else {
		args = append(args, "--to",
			"--id", rightID,
			"--host", "%any",
			"--client", connection.RemoteSubnet)
	}

	if l.keepaliveInterval > 0 && l.keepaliveTimeout > 0 {
		args = append(args, "--dpddelay", strconv.Itoa(l.keepaliveInterval), "--dpdtimeout", strconv.Itoa(l.keepaliveTimeout), "--dpdaction", "restart")
	}

	if err := whackCmd(args...); err != nil {
		return err
	}
	if connection.LocalEndpoint.UnderNAT || (!connection.LocalEndpoint.UnderNAT && !connection.RemoteEndpoint.UnderNAT) {
		if err := whackCmd("--route", "--name", connectionName); err != nil {
			return err
		}
		if err := whackCmd("--initiate", "--asynchronous", "--name", connectionName); err != nil {
			return err
		}
	}
	return nil
}

func (l *libreswan) whackConnectToEdgeEndpoint(connectionName string, connection *vpndriver.Connection) error {
	args := make([]string, 0)
	leftID := fmt.Sprintf("@%s-%s-%s", connection.LocalEndpoint.PrivateIP, connection.LocalSubnet, connection.RemoteSubnet)
	rightID := fmt.Sprintf("@%s-%s-%s", connection.RemoteEndpoint.PrivateIP, connection.RemoteSubnet, connection.LocalSubnet)

	if err := whackCmd("--delete", "--name", connectionName); err != nil {
		return err
	}
	// local
	args = append(args, "--psk", "--encrypt", "--forceencaps", "--name", connectionName,
		"--id", leftID,
		"--host", connection.LocalEndpoint.String(),
		"--client", connection.LocalSubnet)
	// remote
	if connection.RemoteEndpoint.NATType == utils.NATSymmetric {
		args = append(args, "--to",
			"--id", rightID,
			"--host", "%any",
			"--client", connection.RemoteSubnet)
		if err := whackCmd(args...); err != nil {
			return err
		}
		return nil
	}

	args = append(args, "--to",
		"--id", rightID,
		"--host", connection.RemoteEndpoint.PublicIP,
		"--client", connection.RemoteSubnet,
		"--ikeport", strconv.Itoa(connection.RemoteEndpoint.PublicPort))

	if l.keepaliveInterval > 0 && l.keepaliveTimeout > 0 {
		args = append(args, "--dpddelay", strconv.Itoa(l.keepaliveInterval), "--dpdtimeout", strconv.Itoa(l.keepaliveTimeout), "--dpdaction", "restart")
	}

	if err := whackCmd(args...); err != nil {
		return err
	}
	if err := whackCmd("--route", "--name", connectionName); err != nil {
		return err
	}
	if err := whackCmd("--initiate", "--asynchronous", "--name", connectionName); err != nil {
		return err
	}

	return nil
}

func whackCmdFn(args ...string) error {
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
		return fmt.Errorf("error whacking with %v: %v, error %s", args, err, string(output))
	}
	return nil
}

func (l *libreswan) whackDelConnection(conn string) error {
	return whackCmd("--delete", "--name", conn)
}

func connectionName(localID, remoteID, leftSubnet, rightSubnet string) string {
	return fmt.Sprintf("%s-%s-%s-%s", localID, remoteID, leftSubnet, rightSubnet)
}

func (l *libreswan) Cleanup() error {
	errList := errorlist.List{}
	for name := range l.relayConnections {
		if err := l.whackDelConnection(name); err != nil {
			errList = errList.Append(err)
			klog.ErrorS(err, "fail to delete connection", "connectionName", name)
		}
		if l.centralGw != nil && l.centralGw.NodeName == l.nodeName {
			errList = errList.Append(l.deleteRavenSkipNAT(l.relayConnections[name]))
		}
	}
	for name := range l.edgeConnections {
		if err := l.whackDelConnection(name); err != nil {
			errList = errList.Append(err)
			klog.ErrorS(err, "fail to delete connection", "connectionName", name)
		}
	}
	l.relayConnections = make(map[string]*vpndriver.Connection)
	l.edgeConnections = make(map[string]*vpndriver.Connection)
	err := netlinkutil.XfrmPolicyFlush()
	errList = errList.Append(err)

	err = l.iptables.NewChainIfNotExist(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain)
	if err != nil {
		errList = errList.Append(fmt.Errorf("error create %s chain: %s", iptablesutil.PostRoutingChain, err))
	}
	err = l.iptables.DeleteIfExists(iptablesutil.NatTable, iptablesutil.PostRoutingChain, "-m", "comment", "--comment", "raven traffic should skip NAT", "-j", iptablesutil.RavenPostRoutingChain)
	if err != nil {
		errList = errList.Append(fmt.Errorf("error deleting %s chain rule: %s", iptablesutil.PostRoutingChain, err))
	}
	err = l.iptables.ClearAndDeleteChain(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain)
	if err != nil {
		errList = errList.Append(fmt.Errorf("error deleting %s chain %s", iptablesutil.RavenPostRoutingChain, err))
	}
	return errList.AsError()
}

func (l *libreswan) runPluto() error {
	klog.Info("starting pluto")

	cmd := exec.Command("/usr/local/bin/pluto")

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
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

func (l *libreswan) connectToEndpoint(name string, connection *vpndriver.Connection) errorlist.List {
	errList := errorlist.List{}
	if _, ok := l.relayConnections[name]; ok {
		klog.InfoS("skipping connect because connection already exists", "connectionName", name)
		return errList
	}
	err := l.whackConnectToEndpoint(name, connection)
	if err != nil {
		errList = errList.Append(err)
		klog.ErrorS(err, "error connect connection", "connectionName", name)
		return errList
	}
	l.relayConnections[name] = connection
	return errList
}

func (l *libreswan) connectToEdgeEndpoint(name string, connection *vpndriver.Connection) errorlist.List {
	errList := errorlist.List{}
	if _, ok := l.edgeConnections[name]; ok {
		klog.InfoS("skipping connect because connection already exists", "connectionName", name)
		return errList
	}
	err := l.whackConnectToEdgeEndpoint(name, connection)
	if err != nil {
		errList = errList.Append(err)
		klog.ErrorS(err, "error connect connection", "connectionName", name)
		return errList
	}
	l.edgeConnections[name] = connection
	return errList
}
