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

package main

import (
	"flag"
	"os"

	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/pkg/k8s"
)

var (
	kubeconfig string
	nodeName   string
)

func main() {
	klog.InitFlags(nil)
	fs := flag.NewFlagSet("raven", flag.ExitOnError)

	fs.StringVar(&kubeconfig, "kubeconfig", "", "path to a kubeconfig, only required if out-of-cluster.")
	fs.StringVar(&nodeName, "node-name", "", "current node name.")
	if err := fs.Parse(os.Args[1:]); err != nil {
		panic(err)
	}

	ctr, err := k8s.New(&k8s.Config{
		NodeName:   nodeName,
		Kubeconfig: kubeconfig,
	})
	if err != nil {
		klog.Errorf("error create engine controller: %v", err)
	}
	ctr.Start()
}
