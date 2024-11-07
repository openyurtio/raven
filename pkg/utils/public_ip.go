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

package utils

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
)

var (
	APIs = [...]string{
		"https://ifconfig.me",
		"https://icanhazip.com",
		"https://ipinfo.io/json",
		"https://api.ipify.org",
		"https://api.my-ip.io/ip",
		"https://ip4.seeip.org",
	}
)

var IPv4RE = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)

func GetPublicIP() (string, error) {
	for _, api := range APIs {
		ip, err := getFromAPI(api)
		if err == nil {
			return ip, nil
		}
	}
	return "", fmt.Errorf("error get public ip by any of the apis: %v", APIs)
}

func getFromAPI(api string) (string, error) {
	resp, err := http.Get(api)
	if err != nil {
		return "", fmt.Errorf("retrieving public ip from %s: %v", api, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading api response from %s: %v", api, err)
	}
	return parseIPv4(string(body))
}

func parseIPv4(body string) (string, error) {
	matches := IPv4RE.FindAllString(body, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("no ipv4 found in: %q", body)
	}
	return matches[0], nil
}
