# Raven Agent Tutorial 

This document introduces how to install raven and use raven to enhance edge-edge and edge-cloud network communication in an edge cluster. 

Suppose you have an edge kubernetes cluster with nodes in different physical regions, and already deploy the raven-controller-manager in this cluster, the details of raven-controller-manager are in [here](https://github.com/openyurtio/raven-controller-manager/blob/main/README.md).

## Label nodes in different physical regions

As follows, suppose the cluster has five nodes, located in three different regions, where the node `master` is cloud node.
``` bash
$ kubectl get nodes -o wide

NAME         STATUS   ROLES    AGE   VERSION   INTERNAL-IP    
hhht-node1   Ready    <none>   20d   v1.16.2   10.48.115.9    
hhht-node2   Ready    <none>   20d   v1.16.2   10.48.115.10
master       Ready    master   20d   v1.16.2   10.48.115.8
wlcb-node1   Ready    <none>   20d   v1.16.2   10.48.115.11
wlcb-node2   Ready    <none>   20d   v1.16.2   10.48.115.12    
```

We use a [Gateway](https://github.com/openyurtio/raven-controller-manager/blob/main/pkg/ravencontroller/apis/raven/v1alpha1/gateway_types.go) CR to manage nodes in different physical regions, and label nodes to indicate which `Gateway` these nodes are managed by.

For example, We label nodes in region `cn-huhehaote` with value `gw-hhht`, indicating that these nodes are managed by the `gw-hhht` gateway.
```bash
$ kubectl label nodes hhht-node1 hhht-node2 raven.openyurt.io/gateway=gw-hhht
hhht-node1 labeled
hhht-node2 labeled
```

Similarly, we label node in `cloud` with value `gw-cloud`, and nodes in region `cn-wulanchabu` with value `gw-wlcb`.
```bash
$ kubectl label nodes master raven.openyurt.io/gateway=gw-cloud
master labeled
```

```bash
$ kubectl label nodes wlcb-node1 wlcb-node2 raven.openyurt.io/gateway=gw-wlcb
wlcb-node1 labeled
wlcb-node2 labeled
```

### install raven agent
```bash
$ cd raven
$ make deploy
```

Wait for the raven agent daemon to be created successfully
``` bash
$ kubectl get pod -n kube-system | grep raven-agent-ds
raven-agent-ds-2jw47                           1/1     Running   0          91s
raven-agent-ds-bq8zc                           1/1     Running   0          91s
raven-agent-ds-cj7k4                           1/1     Running   0          91s
raven-agent-ds-p9fk9                           1/1     Running   0          91s
raven-agent-ds-rlb9q                           1/1     Running   0          91s
```

## How to Use

### Gateways 

- 1 create gateways
```bash
$ cat <<EOF | kubectl apply -f -
apiVersion: raven.openyurt.io/v1alpha1
kind: Gateway
metadata:
  name: gw-hhht
spec:
  endpoints:
    - nodeName: hhht-node1
      underNAT: true
    - nodeName: hhht-node2
      underNAT: true
      
---
apiVersion: raven.openyurt.io/v1alpha1
kind: Gateway
metadata:
  name: gw-cloud
spec:
  endpoints:
    - nodeName: master
      underNAT: false
      
---
apiVersion: raven.openyurt.io/v1alpha1
kind: Gateway
metadata:
  name: gw-wlcb
spec:
  endpoints:
    - nodeName: wlcb-node1
      underNAT: true
    - nodeName: wlcb-node2
      underNAT: true

EOF
```

- 2 Get gateways
```bash
$ kubectl get gateways

NAME      ACTIVEENDPOINT
gw-hhht   hhht-node1
gw-master master
gw-wlcb   wlcb-node1
```

 ### Test pod-to-pod networking

- 1 Create test pod
```bash
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: fedora-1
spec:
  nodeName: hhht-node2
  containers:
    - name: fedora
      image: njucjc/fedora:latest
      imagePullPolicy: Always

---

apiVersion: v1
kind: Pod
metadata:
  name: fedora-2
spec:
  nodeName: wlcb-node2
  containers:
    - name: fedora
      image: njucjc/fedora:latest
      imagePullPolicy: Always


EOF
```

- 2 Get test pod

```bash
$ kubectl get pod -o wide
NAME       READY   STATUS    RESTARTS   AGE     IP            NODE                  NOMINATED NODE   READINESS GATES
fedora-1   1/1     Running   0          46s     10.14.10.67   hhht-node2            <none>           <none>
fedora-2   1/1     Running   0          46s     10.14.2.70    wlcb-node2            <none>           <none>

```

- 3 Test networking across edge

```bash
$ kubectl exec -it fedora-1 -- bash
[root@fedora-1]# ping 10.14.2.70 -c 4
PING 10.14.2.70 (10.14.2.70) 56(84) bytes of data.
64 bytes from 10.14.2.70: icmp_seq=1 ttl=60 time=32.2 ms
64 bytes from 10.14.2.70: icmp_seq=2 ttl=60 time=32.2 ms
64 bytes from 10.14.2.70: icmp_seq=3 ttl=60 time=32.0 ms
64 bytes from 10.14.2.70: icmp_seq=4 ttl=60 time=32.1 ms

--- 10.14.2.70 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3003ms
rtt min/avg/max/mdev = 32.047/32.136/32.246/0.081 ms

```