package routing

import (
	"fmt"
	"time"

	"github.com/prometheus-community/pro-bing"
)

// LatencyProber is an interface for measuring network latency to a given IP address.
type LatencyProber interface {
	ProbeCost(targetIP string) (int, error)
}

// ICMPProber implements LatencyProber using ICMP Echo Requests.
type ICMPProber struct {
	Count   int
	Timeout time.Duration
}

// NewICMPProber creates a new ICMP prober.
func NewICMPProber() *ICMPProber {
	return &ICMPProber{
		Count:   1,               // 1 ping for quick check
		Timeout: 1 * time.Second, // Timeout quickly if unreachable
	}
}

// ProbeCost pings the target IP and returns the RTT in milliseconds.
func (p *ICMPProber) ProbeCost(targetIP string) (int, error) {
	if targetIP == "" {
		return 0, fmt.Errorf("target IP is empty")
	}
	pinger, err := probing.NewPinger(targetIP)
	if err != nil {
		return 0, fmt.Errorf("failed to create pinger: %w", err)
	}

	// We run as a privileged container, so we need to enable privileged ping (raw sockets)
	pinger.SetPrivileged(true)
	pinger.Count = p.Count
	pinger.Timeout = p.Timeout

	err = pinger.Run()
	if err != nil {
		return 0, fmt.Errorf("ping execution failed: %w", err)
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return 0, fmt.Errorf("100%% packet loss to %s", targetIP)
	}

	// Cost is RTT in milliseconds (at least 1 ms if successful to avoid 0 cost links)
	costMs := int(stats.AvgRtt.Milliseconds())
	if costMs == 0 {
		costMs = 1
	}
	return costMs, nil
}
