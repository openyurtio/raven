package routing

import (
	"fmt"
	"testing"

	"github.com/openyurtio/raven/pkg/types"
)

func TestComputeShortestPaths(t *testing.T) {
	gateways := map[types.GatewayName]*types.Endpoint{
		"gw-a": {},
		"gw-b": {},
		"gw-c": {},
		"gw-d": {},
	}

	// gw-a is the local gateway
	localGw := types.GatewayName("gw-a")

	// Create a topology: A -> B (cost 10), B -> C (cost 10), A -> C (cost 50), C -> D (cost 10)
	// Shortest path to C should be A -> B -> C (cost 20) instead of A -> C (cost 50).
	// Shortest path to D should be A -> B -> C -> D (cost 30).
	linkCosts := map[types.GatewayName]map[types.GatewayName]int{
		"gw-a": {
			"gw-b": 10,
			"gw-c": 50,
		},
		"gw-b": {
			"gw-a": 10,
			"gw-c": 10,
		},
		"gw-c": {
			"gw-a": 50,
			"gw-b": 10,
			"gw-d": 10,
		},
		"gw-d": {
			"gw-c": 10,
		},
	}

	routeTable := ComputeShortestPaths(localGw, gateways, linkCosts)

	fmt.Println("--- Manual Testing Output for Shortest Path Decision ---")
	for _, route := range routeTable {
		fmt.Printf("Destination: %s | NextHop: %s | Total Cost: %d\n", route.Destination, route.NextHop, route.Cost)
	}
	fmt.Println("--------------------------------------------------------")

	// Assertions for manual validation
	if routeTable["gw-c"].Cost != 20 {
		t.Errorf("Expected cost to gw-c to be 20, got %d", routeTable["gw-c"].Cost)
	}
	if routeTable["gw-c"].NextHop != "gw-b" {
		t.Errorf("Expected next hop to gw-c to be gw-b, got %s", routeTable["gw-c"].NextHop)
	}
}
