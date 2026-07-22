/*
Copyright 2023 The OpenYurt Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package routing

import (
	"math"

	"github.com/openyurtio/raven/pkg/types"
)

// ComputeShortestPaths uses Dijkstra's algorithm to compute the shortest paths from the local gateway
// to all other remote gateways based on the provided link costs.
func ComputeShortestPaths(
	localGw types.GatewayName,
	gateways map[types.GatewayName]*types.Endpoint,
	linkCosts map[types.GatewayName]map[types.GatewayName]int,
) map[types.GatewayName]types.RouteEntry {
	
	routeTable := make(map[types.GatewayName]types.RouteEntry)
	
	dist := make(map[types.GatewayName]int)
	prev := make(map[types.GatewayName]types.GatewayName)
	unvisited := make(map[types.GatewayName]bool)

	// Initialize distances
	for gw := range gateways {
		dist[gw] = math.MaxInt32
		unvisited[gw] = true
	}
	if localGw != "" {
		dist[localGw] = 0
		unvisited[localGw] = true
	}

	for len(unvisited) > 0 {
		// Find node with minimum distance
		var u types.GatewayName
		minDist := math.MaxInt32
		for node := range unvisited {
			if dist[node] < minDist {
				minDist = dist[node]
				u = node
			}
		}

		if u == "" || minDist == math.MaxInt32 {
			break // All remaining vertices are inaccessible
		}
		delete(unvisited, u)

		// Update distances for neighbors
		if neighbors, ok := linkCosts[u]; ok {
			for v, cost := range neighbors {
				if unvisited[v] {
					alt := dist[u] + cost
					if alt < dist[v] {
						dist[v] = alt
						prev[v] = u
					}
				}
			}
		}
	}

	// Build routing table (next hop)
	for gw := range gateways {
		if gw == localGw || dist[gw] == math.MaxInt32 {
			continue
		}
		
		// Trace back to find the next hop from localGw
		curr := gw
		for prev[curr] != localGw && prev[curr] != "" {
			curr = prev[curr]
		}
		
		if prev[curr] == localGw {
			routeTable[gw] = types.RouteEntry{
				Destination: gw,
				NextHop:     curr,
				Cost:        dist[gw],
			}
		}
	}

	return routeTable
}
