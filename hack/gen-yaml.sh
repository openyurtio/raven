#!/bin/bash
#
# Copyright 2022 The OpenYurt Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

YURT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

gen_yaml() {
    local IMG=$1
    local VPN_DRIVER=$2
    local FORWARD_NODE_IP=$3
    local METRIC_BIND_ADDR=$4
    local NAT_TRAVERSAL=$5
    local OUT_YAML_DIR=${YURT_ROOT}/_output/yamls
    local BUILD_YAML_DIR=${OUT_YAML_DIR}/build
    [ -f "${BUILD_YAML_DIR}" ] || mkdir -p "${BUILD_YAML_DIR}"
    mkdir -p "${BUILD_YAML_DIR}"
    (
        rm -rf "${BUILD_YAML_DIR}"/raven-agent
        cp -rf "${YURT_ROOT}"/config/raven-agent/* "${BUILD_YAML_DIR}"
        cd "${BUILD_YAML_DIR}"/agent || exit
        kustomize edit set image raven-agent="${IMG}"
	)
    set +x
    echo "==== create raven-agent.yaml in $OUT_YAML_DIR ===="
    [ -f "${BUILD_YAML_DIR}"/default/psk.env ] || echo "vpn-connection-psk=$(openssl rand -hex 64)" > "${BUILD_YAML_DIR}"/default/psk.env
    [ -f "${BUILD_YAML_DIR}"/default/config.env ] || echo "vpn-driver=${VPN_DRIVER}" > "${BUILD_YAML_DIR}"/default/config.env
    echo "forward-node-ip=${FORWARD_NODE_IP}" >> "${BUILD_YAML_DIR}"/default/config.env
    echo "metric-bind-addr=${METRIC_BIND_ADDR}" >> "${BUILD_YAML_DIR}"/default/config.env
    echo "nat-traversal=${NAT_TRAVERSAL}" >> "${BUILD_YAML_DIR}"/default/config.env
    kustomize build "${BUILD_YAML_DIR}"/default > "${OUT_YAML_DIR}"/raven-agent.yaml
    rm -Rf "${BUILD_YAML_DIR}"
}

gen_yaml "$@"