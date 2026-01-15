package options

import (
	"os"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openyurtio/raven/pkg/networkengine/routedriver/vxlan"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver/libreswan"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver/wireguard"
	"github.com/openyurtio/raven/pkg/utils"
)

func TestAgentOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		options *AgentOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid options with libreswan",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: false,
		},
		{
			name: "valid options with wireguard",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: wireguard.DriverName,
					MACPrefix: "aa:0f",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: false,
		},
		{
			name: "missing node name",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f",
				},
				NodeName:   "",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: true,
			errMsg:  "either --node-name or $NODE_NAME has to be set",
		},
		{
			name: "missing node IP",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f",
				},
				NodeName:   "test-node",
				NodeIP:     "",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: true,
			errMsg:  "either --node-ip or $NODE_IP has to be set",
		},
		{
			name: "invalid VPN driver",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: "invalid-driver",
					MACPrefix: "aa:0f",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: true,
			errMsg:  "currently only supports libreswan and wireguard VPN drivers",
		},
		{
			name: "valid MAC prefix with single segment",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: false,
		},
		{
			name: "valid MAC prefix with multiple segments",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f:12:34",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: false,
		},
		{
			name: "valid MAC prefix with uppercase hex",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "AA:0F:12:34",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: false,
		},
		{
			name: "invalid MAC prefix with non-hex characters",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0g",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: true,
			errMsg:  "mac prefix",
		},
		{
			name: "invalid MAC prefix with special characters",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f:xy",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: true,
			errMsg:  "mac prefix",
		},
		{
			name: "empty MAC prefix",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: true,
			errMsg:  "mac prefix",
		},
		{
			name: "sync period less than 1 minute - should be adjusted",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 30 * time.Second},
			},
			wantErr: false,
		},
		{
			name: "sync period greater than 24 hours - should be adjusted",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 25 * time.Hour},
			},
			wantErr: false,
		},
		{
			name: "sync period at minimum boundary",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: time.Minute},
			},
			wantErr: false,
		},
		{
			name: "sync period at maximum boundary",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f",
				},
				NodeName:   "test-node",
				NodeIP:     "192.168.1.1",
				SyncPeriod: metav1.Duration{Duration: 24 * time.Hour},
			},
			wantErr: false,
		},
		{
			name: "multiple validation errors - should return first error",
			options: &AgentOptions{
				TunnelOptions: TunnelOptions{
					VPNDriver: libreswan.DriverName,
					MACPrefix: "aa:0f",
				},
				NodeName:   "",
				NodeIP:     "",
				SyncPeriod: metav1.Duration{Duration: 10 * time.Minute},
			},
			wantErr: true,
			errMsg:  "either --node-name or $NODE_NAME has to be set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Store original sync period to check if it was adjusted
			originalSyncPeriod := tt.options.SyncPeriod.Duration

			err := tt.options.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" {
				if err.Error() != tt.errMsg && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, want error containing %v", err, tt.errMsg)
				}
			}

			// Check sync period adjustments
			if !tt.wantErr {
				if originalSyncPeriod < time.Minute && tt.options.SyncPeriod.Duration != time.Minute {
					t.Errorf("Validate() should adjust sync period from %v to %v, got %v",
						originalSyncPeriod, time.Minute, tt.options.SyncPeriod.Duration)
				}
				if originalSyncPeriod > 24*time.Hour && tt.options.SyncPeriod.Duration != 24*time.Hour {
					t.Errorf("Validate() should adjust sync period from %v to %v, got %v",
						originalSyncPeriod, 24*time.Hour, tt.options.SyncPeriod.Duration)
				}
			}
		})
	}
}

func TestNewDefaultOptions(t *testing.T) {
	// Save original environment variables
	originalNodeName := os.Getenv("NODE_NAME")
	originalNodeIP := os.Getenv("NODE_IP")

	// Clean up after test
	defer func() {
		if originalNodeName != "" {
			_ = os.Setenv("NODE_NAME", originalNodeName)
		} else {
			_ = os.Unsetenv("NODE_NAME")
		}
		if originalNodeIP != "" {
			_ = os.Setenv("NODE_IP", originalNodeIP)
		} else {
			_ = os.Unsetenv("NODE_IP")
		}
	}()

	tests := []struct {
		name                         string
		setNodeName                  string
		setNodeIP                    string
		wantNodeName                 string
		wantNodeIP                   string
		wantVPNDriver                string
		wantRouteDriver              string
		wantVPNPort                  string
		wantMACPrefix                string
		wantProxyClientCertDir       string
		wantProxyServerCertDir       string
		wantInterceptorServerUDSFile string
	}{
		{
			name:                         "default options with environment variables set",
			setNodeName:                  "test-node-1",
			setNodeIP:                    "192.168.1.100",
			wantNodeName:                 "test-node-1",
			wantNodeIP:                   "192.168.1.100",
			wantVPNDriver:                libreswan.DriverName,
			wantRouteDriver:              vxlan.DriverName,
			wantVPNPort:                  vpndriver.DefaultVPNPort,
			wantMACPrefix:                "aa:0f",
			wantProxyClientCertDir:       utils.RavenProxyClientCertDir,
			wantProxyServerCertDir:       utils.RavenProxyServerCertDir,
			wantInterceptorServerUDSFile: utils.RavenProxyServerUDSFile,
		},
		{
			name:                         "default options without environment variables",
			setNodeName:                  "",
			setNodeIP:                    "",
			wantNodeName:                 "",
			wantNodeIP:                   "",
			wantVPNDriver:                libreswan.DriverName,
			wantRouteDriver:              vxlan.DriverName,
			wantVPNPort:                  vpndriver.DefaultVPNPort,
			wantMACPrefix:                "aa:0f",
			wantProxyClientCertDir:       utils.RavenProxyClientCertDir,
			wantProxyServerCertDir:       utils.RavenProxyServerCertDir,
			wantInterceptorServerUDSFile: utils.RavenProxyServerUDSFile,
		},
		{
			name:                         "default options with partial environment variables",
			setNodeName:                  "test-node-2",
			setNodeIP:                    "",
			wantNodeName:                 "test-node-2",
			wantNodeIP:                   "",
			wantVPNDriver:                libreswan.DriverName,
			wantRouteDriver:              vxlan.DriverName,
			wantVPNPort:                  vpndriver.DefaultVPNPort,
			wantMACPrefix:                "aa:0f",
			wantProxyClientCertDir:       utils.RavenProxyClientCertDir,
			wantProxyServerCertDir:       utils.RavenProxyServerCertDir,
			wantInterceptorServerUDSFile: utils.RavenProxyServerUDSFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variables
			if tt.setNodeName != "" {
				_ = os.Setenv("NODE_NAME", tt.setNodeName)
			} else {
				_ = os.Unsetenv("NODE_NAME")
			}
			if tt.setNodeIP != "" {
				_ = os.Setenv("NODE_IP", tt.setNodeIP)
			} else {
				_ = os.Unsetenv("NODE_IP")
			}

			// Call the function
			got := NewDefaultOptions()

			// Verify the result
			if got == nil {
				t.Fatal("NewDefaultOptions() returned nil")
			}

			// Verify TunnelOptions
			if got.VPNDriver != tt.wantVPNDriver {
				t.Errorf("NewDefaultOptions().VPNDriver = %v, want %v", got.VPNDriver, tt.wantVPNDriver)
			}
			if got.RouteDriver != tt.wantRouteDriver {
				t.Errorf("NewDefaultOptions().RouteDriver = %v, want %v", got.RouteDriver, tt.wantRouteDriver)
			}
			if got.VPNPort != tt.wantVPNPort {
				t.Errorf("NewDefaultOptions().VPNPort = %v, want %v", got.VPNPort, tt.wantVPNPort)
			}
			if got.MACPrefix != tt.wantMACPrefix {
				t.Errorf("NewDefaultOptions().MACPrefix = %v, want %v", got.MACPrefix, tt.wantMACPrefix)
			}

			// Verify ProxyOptions
			if got.ProxyClientCertDir != tt.wantProxyClientCertDir {
				t.Errorf("NewDefaultOptions().ProxyClientCertDir = %v, want %v", got.ProxyClientCertDir, tt.wantProxyClientCertDir)
			}
			if got.ProxyServerCertDir != tt.wantProxyServerCertDir {
				t.Errorf("NewDefaultOptions().ProxyServerCertDir = %v, want %v", got.ProxyServerCertDir, tt.wantProxyServerCertDir)
			}
			if got.InterceptorServerUDSFile != tt.wantInterceptorServerUDSFile {
				t.Errorf("NewDefaultOptions().InterceptorServerUDSFile = %v, want %v", got.InterceptorServerUDSFile, tt.wantInterceptorServerUDSFile)
			}

			// Verify NodeName and NodeIP from environment
			if got.NodeName != tt.wantNodeName {
				t.Errorf("NewDefaultOptions().NodeName = %v, want %v", got.NodeName, tt.wantNodeName)
			}
			if got.NodeIP != tt.wantNodeIP {
				t.Errorf("NewDefaultOptions().NodeIP = %v, want %v", got.NodeIP, tt.wantNodeIP)
			}

			// Verify default values for other fields
			if got.ForwardNodeIP != false {
				t.Errorf("NewDefaultOptions().ForwardNodeIP = %v, want false", got.ForwardNodeIP)
			}
			if got.NATTraversal != false {
				t.Errorf("NewDefaultOptions().NATTraversal = %v, want false", got.NATTraversal)
			}
			if got.KeepAliveInterval != 0 {
				t.Errorf("NewDefaultOptions().KeepAliveInterval = %v, want 0", got.KeepAliveInterval)
			}
			if got.KeepAliveTimeout != 0 {
				t.Errorf("NewDefaultOptions().KeepAliveTimeout = %v, want 0", got.KeepAliveTimeout)
			}
		})
	}
}
