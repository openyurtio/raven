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
	"time"

	"github.com/openyurtio/openyurt/pkg/apis/raven/v1alpha1"
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
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
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
	// ListenPort specifies port of WireGuard listened.
	ListenPort = 4500
)

var findCentralGw = vpndriver.FindCentralGwFn

var _ vpndriver.Driver = (*wireguard)(nil)

func init() {
	vpndriver.RegisterDriver(DriverName, New)
}

type wireguard struct {
	wgClient   *wgctrl.Client
	privateKey wgtypes.Key
	psk        wgtypes.Key
	wgLink     netlink.Link

	connections map[string]*vpndriver.Connection
	nodeName    types.NodeName
	ravenClient client.Client
}

func New(cfg *config.Config) (vpndriver.Driver, error) {
	return &wireguard{
		connections: make(map[string]*vpndriver.Connection),
		nodeName:    types.NodeName(cfg.NodeName),
		ravenClient: cfg.Manager.GetClient(),
	}, nil
}

func (w *wireguard) Init() error {
	var err error
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
		if d.ListenPort == ListenPort && reflect.DeepEqual(d.PrivateKey, w.privateKey) {
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

	port := ListenPort
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
	// 1. Compute desiredConnections
	centralGw := findCentralGw(network)
	desiredConnections, centralAllowedIPs := w.computeDesiredConnections(network)
	if len(desiredConnections) == 0 {
		klog.Infof("no desired connections, cleaning vpn connections")
		return w.Cleanup()
	}

	// 2. Ensure  WireGuard link
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

	// 4. delete unwanted connections
	for connName, connection := range w.connections {
		if _, ok := desiredConnections[connName]; !ok {
			remoteKey := keyFromEndpoint(connection.RemoteEndpoint)
			if err := w.removePeer(remoteKey); err == nil {
				delete(w.connections, connName)
			}
		}
	}

	// 5. add or update connections
	peerConfigs := make([]wgtypes.PeerConfig, 0)
	for name, newConn := range desiredConnections {
		newKey := keyFromEndpoint(newConn.RemoteEndpoint)

		if oldConn, ok := w.connections[name]; ok {
			oldKey := keyFromEndpoint(oldConn.RemoteEndpoint)
			if oldKey.String() != newKey.String() {
				if err := w.removePeer(oldKey); err == nil {
					delete(w.connections, name)
				}
			}
		}

		klog.InfoS("create connection", "c", newConn)

		allowedIPs := parseSubnets(newConn.RemoteEndpoint.Subnets)
		if newConn.RemoteEndpoint.NodeName == centralGw.NodeName {
			allowedIPs = append(allowedIPs, parseSubnets(centralAllowedIPs)...)
		}

		remotePort := ListenPort
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

	w.connections = desiredConnections

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
	w.connections = make(map[string]*vpndriver.Connection)
	return errList.AsError()
}

func (w *wireguard) computeDesiredConnections(network *types.Network) (map[string]*vpndriver.Connection, []string) {

	// This is the desired connection calculated from given *types.Network
	desiredConns := make(map[string]*vpndriver.Connection)
	centralAllowedIPs := make([]string, 0)
	for _, remote := range network.RemoteEndpoints {
		if _, ok := remote.Config[PublicKey]; !ok {
			continue
		}

		// if local gateway is not central gateway and remote endpoint is NATed
		// append all subnets of remote gateway into central allowed IPs.
		if network.LocalEndpoint.UnderNAT && remote.UnderNAT {
			centralAllowedIPs = append(centralAllowedIPs, remote.Subnets...)
			continue
		}

		name := connectionName(string(network.LocalEndpoint.NodeName), string(remote.NodeName))
		desiredConns[name] = &vpndriver.Connection{
			LocalEndpoint:  network.LocalEndpoint.Copy(),
			RemoteEndpoint: remote.Copy(),
		}
	}
	return desiredConns, centralAllowedIPs
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
		var apiGw v1alpha1.Gateway
		err := w.ravenClient.Get(context.Background(), client.ObjectKey{
			Name: gwName,
		}, &apiGw)
		if err != nil {
			return err
		}
		for k, v := range apiGw.Spec.Endpoints {
			if v.NodeName == nodeName {
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
