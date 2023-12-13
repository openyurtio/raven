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

package wireguard

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/pkg/errors"
	"github.com/vdobler/ht/errorlist"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	networkutil "github.com/openyurtio/raven/pkg/networkengine/util"
	iptablesutil "github.com/openyurtio/raven/pkg/networkengine/util/iptables"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/openyurtio/raven/pkg/utils"
)

const (
	wgRouteTableID = 9028
	wgRulePriority = 101
	wgEncapLen     = 80
	wgLinkType     = "wireguard"

	// DriverName specifies name of WireGuard VPN backend driver.
	DriverName = "wireguard"
	// PublicKey is name (key) of publicKey entry in back-end map.
	PublicKey = "publicKey"
	// KeepAliveInterval to use for wg peers.
	KeepAliveInterval = 5 * time.Second

	// DeviceName specifies name of WireGuard network device.
	DeviceName = "raven-wg0"
	// DefaultListenPort specifies port of WireGuard listened.
	DefaultListenPort = 4500
)

var findCentralGw = vpndriver.FindCentralGwFn
var enableCreateEdgeConnection = vpndriver.EnableCreateEdgeConnection

var _ vpndriver.Driver = (*wireguard)(nil)

func init() {
	vpndriver.RegisterDriver(DriverName, New)
}

type wireguard struct {
	wgClient   *wgctrl.Client
	privateKey wgtypes.Key
	psk        wgtypes.Key
	wgLink     netlink.Link

	relayConnections map[string]*vpndriver.Connection
	edgeConnections  map[string]*vpndriver.Connection
	iptables         iptablesutil.IPTablesInterface
	nodeName         types.NodeName
	ravenClient      client.Client
	listenPort       int
}

func New(cfg *config.Config) (vpndriver.Driver, error) {
	port, err := strconv.Atoi(cfg.Tunnel.VPNPort)
	if err != nil {
		port = DefaultListenPort
	}
	return &wireguard{
		relayConnections: make(map[string]*vpndriver.Connection),
		edgeConnections:  make(map[string]*vpndriver.Connection),
		nodeName:         types.NodeName(cfg.NodeName),
		ravenClient:      cfg.Manager.GetClient(),
		listenPort:       port,
	}, nil
}

func (w *wireguard) Init() error {
	var err error
	w.iptables, err = iptablesutil.New()
	if err != nil {
		return err
	}
	// Create the WireGuard controller.
	w.wgClient, err = wgctrl.New()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("wgctrl is not available on this system")
		}
		return fmt.Errorf("failed to open wgctl client: %v", err)
	}
	defer func() {
		if err != nil && w.wgClient != nil {
			if e := w.wgClient.Close(); e != nil {
				klog.Errorf("failed to close client: %v", e)
			}
		}
	}()

	// Generating keys
	pskBytes := sha256.Sum256([]byte(vpndriver.GetPSK()))
	if w.psk, err = wgtypes.NewKey(pskBytes[:]); err != nil {
		return fmt.Errorf("error get pre-shared key: %v", err)
	}

	if w.privateKey, err = wgtypes.GeneratePrivateKey(); err != nil {
		return fmt.Errorf("error generating private key: %v", err)
	}

	return nil
}

func (w *wireguard) isWgDeviceChanged(existing, desired netlink.Link) bool {
	if d, err := w.wgClient.Device(DeviceName); err == nil {
		if d.ListenPort == w.listenPort && reflect.DeepEqual(d.PrivateKey, w.privateKey) {
			return false
		}
	}
	if existing.Attrs().MTU == desired.Attrs().MTU {
		return false
	}
	return true
}

// ensureWgLink creates new wg link if not exists.
func (w *wireguard) ensureWgLink(network *types.Network, routeDriverMTUFn func(*types.Network) (int, error)) error {
	var err error
	var vpnRouteMTU, routeDriverMTU int
	vpnRouteMTU, err = w.MTU()
	if err != nil {
		return err
	}
	routeDriverMTU, err = routeDriverMTUFn(network)
	if err != nil {
		return err
	}

	// Config wg link
	la := netlink.NewLinkAttrs()
	la.Name = DeviceName
	if vpnRouteMTU > routeDriverMTU {
		la.MTU = routeDriverMTU
	} else {
		la.MTU = vpnRouteMTU
	}
	wgLink := &netlink.GenericLink{
		LinkAttrs: la,
		LinkType:  wgLinkType,
	}

	// Delete existing wg link if needed
	wgLinkExist, err := netlink.LinkByName(DeviceName)
	if err == nil {
		// delete existing device if not wireguard type.
		if w.isWgDeviceChanged(wgLink, wgLinkExist) {
			klog.InfoS("wireguard device changed", "link", wgLinkExist)
			if err := netlink.LinkDel(wgLinkExist); err != nil {
				return fmt.Errorf("error delete existing link: %v", err)
			}
		} else {
			w.wgLink = wgLinkExist
			return nil
		}
	}

	// Create the wg link (ip link add dev $DeviceName type wireguard).
	if err := netlink.LinkAdd(wgLink); err != nil {
		return fmt.Errorf("failed to add WireGuard device: %v", err)
	}

	port := w.listenPort
	// Init Configure the device.
	peerConfigs := make([]wgtypes.PeerConfig, 0)
	cfg := wgtypes.Config{
		PrivateKey:   &w.privateKey,
		ListenPort:   &port,
		FirewallMark: nil,
		ReplacePeers: true,
		Peers:        peerConfigs,
	}

	if err = w.wgClient.ConfigureDevice(DeviceName, cfg); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %v", err)
	}

	if err = netlink.LinkSetUp(wgLink); err != nil {
		return fmt.Errorf("failed to setup wireguard device: %v", err)
	}
	w.wgLink = wgLink
	return nil
}

func (w *wireguard) createConnections(network *types.Network) error {
	desiredEdgeConns, desiredRelayConns, centralAllowedIPs := w.computeDesiredConnections(network)
	if len(desiredEdgeConns) == 0 && len(desiredRelayConns) == 0 {
		klog.Infof("no desired connections, cleaning vpn connections")
		return w.Cleanup()
	}

	klog.Infof("desired edge connections: %+v, desired relay connections: %+v", desiredEdgeConns, desiredRelayConns)

	centralGw := findCentralGw(network)
	if err := w.createEdgeConnections(desiredEdgeConns); err != nil {
		return err
	}
	if err := w.createRelayConnections(desiredRelayConns, centralAllowedIPs, centralGw); err != nil {
		return err
	}

	return nil
}

func (w *wireguard) createEdgeConnections(desiredEdgeConns map[string]*vpndriver.Connection) error {
	if len(desiredEdgeConns) == 0 {
		klog.Infof("no desired edge connections")
		return nil
	}

	for connName, connection := range w.edgeConnections {
		if _, ok := desiredEdgeConns[connName]; !ok {
			remoteKey := keyFromEndpoint(connection.RemoteEndpoint)
			if err := w.removePeer(remoteKey); err == nil {
				delete(w.edgeConnections, connName)
			}
		}
	}

	peerConfigs := make([]wgtypes.PeerConfig, 0)
	for name, newConn := range desiredEdgeConns {
		newKey := keyFromEndpoint(newConn.RemoteEndpoint)

		if oldConn, ok := w.edgeConnections[name]; ok {
			oldKey := keyFromEndpoint(oldConn.RemoteEndpoint)
			if oldKey.String() != newKey.String() {
				if err := w.removePeer(oldKey); err == nil {
					delete(w.edgeConnections, name)
				}
			}
		}

		klog.InfoS("create edge-to-edge connection", "c", newConn)

		allowedIPs := parseSubnets(newConn.RemoteEndpoint.Subnets)
		var remotePort int
		if newConn.RemoteEndpoint.NATType == utils.NATSymmetric {
			remotePort = w.listenPort
		} else {
			remotePort = newConn.RemoteEndpoint.PublicPort
		}
		ka := KeepAliveInterval
		peerConfigs = append(peerConfigs, wgtypes.PeerConfig{
			PublicKey:    *newKey,
			Remove:       false,
			UpdateOnly:   false,
			PresharedKey: &w.psk,
			Endpoint: &net.UDPAddr{
				IP:   net.ParseIP(newConn.RemoteEndpoint.PublicIP),
				Port: remotePort,
			},
			PersistentKeepaliveInterval: &ka,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  allowedIPs,
		})
	}

	if err := w.wgClient.ConfigureDevice(DeviceName, wgtypes.Config{
		ReplacePeers: true,
		Peers:        peerConfigs,
	}); err != nil {
		return fmt.Errorf("error add peers: %v", err)
	}

	w.edgeConnections = desiredEdgeConns

	return nil
}

func (w *wireguard) createRelayConnections(desiredRelayConns map[string]*vpndriver.Connection, centralAllowedIPs []string, centralGw *types.Endpoint) error {
	if len(desiredRelayConns) == 0 {
		klog.Infof("no desired relay connections")
		return nil
	}

	// delete unwanted connections
	for connName, connection := range w.relayConnections {
		if _, ok := desiredRelayConns[connName]; !ok {
			remoteKey := keyFromEndpoint(connection.RemoteEndpoint)
			if err := w.removePeer(remoteKey); err == nil {
				delete(w.relayConnections, connName)
			}
		}
	}

	// add or update connections
	peerConfigs := make([]wgtypes.PeerConfig, 0)
	for name, newConn := range desiredRelayConns {
		newKey := keyFromEndpoint(newConn.RemoteEndpoint)

		if oldConn, ok := w.relayConnections[name]; ok {
			oldKey := keyFromEndpoint(oldConn.RemoteEndpoint)
			if oldKey.String() != newKey.String() {
				if err := w.removePeer(oldKey); err == nil {
					delete(w.relayConnections, name)
				}
			}
		}

		klog.InfoS("create connection", "c", newConn)

		allowedIPs := parseSubnets(newConn.RemoteEndpoint.Subnets)
		if newConn.RemoteEndpoint.NodeName == centralGw.NodeName {
			allowedIPs = append(allowedIPs, parseSubnets(centralAllowedIPs)...)
		}

		remotePort := w.listenPort
		ka := KeepAliveInterval
		peerConfigs = append(peerConfigs, wgtypes.PeerConfig{
			PublicKey:    *newKey,
			Remove:       false,
			UpdateOnly:   false,
			PresharedKey: &w.psk,
			Endpoint: &net.UDPAddr{
				IP:   net.ParseIP(newConn.RemoteEndpoint.PublicIP),
				Port: remotePort,
			},
			PersistentKeepaliveInterval: &ka,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  allowedIPs,
		})
	}

	if err := w.wgClient.ConfigureDevice(DeviceName, wgtypes.Config{
		ReplacePeers: false,
		Peers:        peerConfigs,
	}); err != nil {
		return fmt.Errorf("error add peers: %v", err)
	}

	w.relayConnections = desiredRelayConns

	return nil
}

func (w *wireguard) Apply(network *types.Network, routeDriverMTUFn func(*types.Network) (int, error)) error {
	if network.LocalEndpoint == nil || len(network.RemoteEndpoints) == 0 {
		klog.Info("no local gateway or remote gateway is found, cleaning vpn connections")
		return w.Cleanup()
	}
	if network.LocalEndpoint.NodeName != w.nodeName {
		klog.Infof("the current node is not gateway node, cleaning vpn connections")
		return w.Cleanup()
	}

	if _, ok := network.LocalEndpoint.Config[PublicKey]; !ok || network.LocalEndpoint.Config[PublicKey] != w.privateKey.PublicKey().String() {
		err := w.configGatewayPublicKey(string(network.LocalEndpoint.GatewayName), string(network.LocalEndpoint.NodeName))
		if err != nil {
			klog.ErrorS(err, "error config gateway public key", "gateway", network.LocalEndpoint.GatewayName)
		}
		return errors.New("retry to config public key")
	}

	centralGw := findCentralGw(network)
	if centralGw.NodeName == w.nodeName {
		if err := w.ensureRavenSkipNAT(); err != nil {
			return fmt.Errorf("error ensure raven skip nat: %s", err)
		}
	}

	if err := w.ensureWgLink(network, routeDriverMTUFn); err != nil {
		return fmt.Errorf("fail to ensure wireguar link: %v", err)
	}
	// 3. Config device route and rules
	currentRoutes, err := networkutil.ListRoutesOnNode(wgRouteTableID)
	if err != nil {
		return fmt.Errorf("error listing wireguard routes on node: %s", err)
	}
	currentRules, err := networkutil.ListRulesOnNode(wgRouteTableID)
	if err != nil {
		return fmt.Errorf("error listing wireguard rules on node: %s", err)
	}

	desiredRoutes := w.calWgRoutes(network)
	desiredRules := w.calWgRules()

	err = networkutil.ApplyRoutes(currentRoutes, desiredRoutes)
	if err != nil {
		return fmt.Errorf("error applying wireguard routes: %s", err)
	}
	err = networkutil.ApplyRules(currentRules, desiredRules)
	if err != nil {
		return fmt.Errorf("error applying wireguard rules: %s", err)
	}

	if err := w.createConnections(network); err != nil {
		return fmt.Errorf("error create VPN tunnels: %v", err)
	}

	return nil
}

func (w *wireguard) MTU() (int, error) {
	mtu, err := vpndriver.DefaultMTU()
	if err != nil {
		return 0, err
	}
	return mtu - wgEncapLen, nil
}

func (w *wireguard) Cleanup() error {
	errList := errorlist.List{}
	if err := networkutil.CleanRulesOnNode(wgRouteTableID); err != nil {
		errList = errList.Append(err)
	}

	if err := networkutil.CleanRoutesOnNode(wgRouteTableID); err != nil {
		errList = errList.Append(err)
	}

	link, err := netlink.LinkByName(DeviceName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return errList.AsError()
	}
	if err != nil {
		errList = errList.Append(fmt.Errorf("error retrieving the wireguard interface %q: %v", DeviceName, err))
		return errList.AsError()
	}

	if err = netlink.LinkDel(link); err != nil {
		errList = errList.Append(fmt.Errorf("error delete existing wireguard device %q: %v", DeviceName, err))
	}

	if err = w.deleteRavenSkipNAT(); err != nil {
		errList = errList.Append(err)
	}

	w.relayConnections = make(map[string]*vpndriver.Connection)
	w.edgeConnections = make(map[string]*vpndriver.Connection)
	return errList.AsError()
}

func (w *wireguard) computeDesiredConnections(network *types.Network) (map[string]*vpndriver.Connection, map[string]*vpndriver.Connection, []string) {
	// This is the desired edge connections and relay connections calculated from given *types.Network
	desiredEdgeConns := make(map[string]*vpndriver.Connection)
	desiredRelayConns := make(map[string]*vpndriver.Connection)
	centralAllowedIPs := make([]string, 0)
	for _, remote := range network.RemoteEndpoints {
		if _, ok := remote.Config[PublicKey]; !ok {
			continue
		}
		name := connectionName(string(network.LocalEndpoint.NodeName), string(remote.NodeName))
		connect := &vpndriver.Connection{
			LocalEndpoint:  network.LocalEndpoint.Copy(),
			RemoteEndpoint: remote.Copy(),
		}
		if enableCreateEdgeConnection(network.LocalEndpoint, remote) {
			desiredEdgeConns[name] = connect
		} else {
			// if local gateway is not central gateway and remote endpoint is NATed
			// append all subnets of remote gateway into central allowed IPs.
			if network.LocalEndpoint.UnderNAT && remote.UnderNAT {
				centralAllowedIPs = append(centralAllowedIPs, remote.Subnets...)
				continue
			}
			desiredRelayConns[name] = connect
		}
	}

	return desiredEdgeConns, desiredRelayConns, centralAllowedIPs
}

func (w *wireguard) removePeer(key *wgtypes.Key) error {

	peerCfg := []wgtypes.PeerConfig{
		{
			PublicKey: *key,
			Remove:    true,
		},
	}

	err := w.wgClient.ConfigureDevice(DeviceName, wgtypes.Config{
		ReplacePeers: false,
		Peers:        peerCfg,
	})
	if err != nil {
		return fmt.Errorf("error remove WireGuard peer with key %s: %v", key, err)
	}

	klog.InfoS("remove peer with key successfully", "key", key.String())

	return nil
}

func (w *wireguard) configGatewayPublicKey(gwName string, nodeName string) error {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// get localGateway from api server
		var apiGw v1beta1.Gateway
		err := w.ravenClient.Get(context.Background(), client.ObjectKey{
			Name: gwName,
		}, &apiGw)
		if err != nil {
			return err
		}
		for k, v := range apiGw.Spec.Endpoints {
			if v.NodeName == nodeName && v.Type == v1beta1.Tunnel {
				if apiGw.Spec.Endpoints[k].Config == nil {
					apiGw.Spec.Endpoints[k].Config = make(map[string]string)
				}
				apiGw.Spec.Endpoints[k].Config[PublicKey] = w.privateKey.PublicKey().String()
				err = w.ravenClient.Update(context.Background(), &apiGw)
				return err
			}
		}
		return nil
	})
	return err
}

// calWgRules calculates and returns the desired WireGuard rules on gateway node.
// Rules on gateway will give raven route table a higher priority than main table in order to bypass the CNI routing rules.
// The rules format are equivalent to the following `ip rule` command:
//
//	ip rule add from all lookup {wgRouteTableID} prio {wgRulePriority}
func (w *wireguard) calWgRules() map[string]*netlink.Rule {
	rules := make(map[string]*netlink.Rule)
	rule := networkutil.NewRavenRule(wgRulePriority, wgRouteTableID)
	rules[networkutil.RuleKey(rule)] = rule
	return rules
}

// calWgRoutes calculates and returns the desired WireGuard routes on gateway node.
// Routes on gateway node will use a separate route table(wg route table),
// The routes entries format are equivalent to the following `ip route` command:
//
//	ip route add {remote_subnet} dev raven-wg0 table {wgRouteTableID}
func (w *wireguard) calWgRoutes(network *types.Network) map[string]*netlink.Route {
	routes := make(map[string]*netlink.Route)
	for _, v := range network.RemoteEndpoints {
		for _, dstCIDR := range v.Subnets {
			_, ipnet, err := net.ParseCIDR(dstCIDR)
			if err != nil {
				klog.ErrorS(err, "error parsing cidr", "cidr", dstCIDR)
				continue
			}
			nr := &netlink.Route{
				LinkIndex: w.wgLink.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       ipnet,
				Table:     wgRouteTableID,
				MTU:       w.wgLink.Attrs().MTU,
			}
			routes[networkutil.RouteKey(nr)] = nr
		}
	}
	return routes
}

func connectionName(localNodeName, remoteNodeName string) string {
	return fmt.Sprintf("%s-%s", localNodeName, remoteNodeName)
}

func keyFromEndpoint(ep *types.Endpoint) *wgtypes.Key {
	s := ep.Config[PublicKey]
	key, _ := wgtypes.ParseKey(s)
	return &key
}

func parseSubnets(subnets []string) []net.IPNet {
	nets := make([]net.IPNet, 0, len(subnets))
	for _, subnet := range subnets {
		_, cidr, err := net.ParseCIDR(subnet)
		if err != nil {
			klog.Errorf("error parse subnet %s: %v", subnet, err)
			continue
		}
		nets = append(nets, *cidr)
	}
	return nets
}

func (w *wireguard) ensureRavenSkipNAT() error {
	// for raven skip nat
	if err := w.iptables.NewChainIfNotExist(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain); err != nil {
		return fmt.Errorf("error create %s chain: %s", iptablesutil.RavenPostRoutingChain, err)
	}
	if err := w.iptables.InsertIfNotExists(iptablesutil.NatTable, iptablesutil.PostRoutingChain, 1, "-m", "comment", "--comment", "raven traffic should skip NAT", "-o", "raven-wg0", "-j", iptablesutil.RavenPostRoutingChain); err != nil {
		return fmt.Errorf("error adding chain %s rule: %s", iptablesutil.PostRoutingChain, err)
	}
	if err := w.iptables.AppendIfNotExists(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("error adding chain %s rule: %s", iptablesutil.RavenPostRoutingChain, err)
	}

	return nil
}

func (w *wireguard) deleteRavenSkipNAT() error {
	if err := w.iptables.NewChainIfNotExist(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain); err != nil {
		return fmt.Errorf("error create %s chain: %s", iptablesutil.PostRoutingChain, err)
	}
	if err := w.iptables.DeleteIfExists(iptablesutil.NatTable, iptablesutil.PostRoutingChain, "-m", "comment", "--comment", "raven traffic should skip NAT", "-o", "raven-wg0", "-j", iptablesutil.RavenPostRoutingChain); err != nil {
		return fmt.Errorf("error deleting %s chain rule: %s", iptablesutil.PostRoutingChain, err)
	}
	if err := w.iptables.ClearAndDeleteChain(iptablesutil.NatTable, iptablesutil.RavenPostRoutingChain); err != nil {
		return fmt.Errorf("error deleting %s chain %s", iptablesutil.RavenPostRoutingChain, err)
	}

	return nil
}
