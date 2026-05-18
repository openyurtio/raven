# Proxy Server Certificate Refresh on Local Gateway PublicIP Change

Status: Draft v3
Author: bingchang
Date: 2026-05-18
Branch: raven-0.5.2

> 修订记录：
> - **v1**（已废弃）：热替证书、不重启 ProxyServer。Reviewer 否决，理由：
>   PublicIP 变化时远端 agent 必须切换到新 IP 重连，已有 TCP 连接在传输层
>   就会断开，热替证书无法保住这些连接。
> - **v2**（已废弃）：抽 `sansolver.go` + `GatewayFingerprint`，引擎层用
>   fingerprint 判定重启。Reviewer 反馈过于复杂。
> - **v3**（本版）：以 PublicIP 集合变化作为重启条件；停止 ProxyServer 时
>   删除服务端证书，启动时 cert manager 因无证书自动触发 CSR，自然带上
>   新的 SAN。

## 1. 背景

Raven 在 Gateway 节点上启动 L7 Proxy Server，使用 `kubernetes.io/kubelet-serving` signer 签发服务端证书。证书 SAN 必须覆盖远端 Proxy Client 实际拨号的所有 PublicIP。

相关代码：

- 证书工厂：`pkg/utils/certmanager/factory/factory.go`
- 文件存储封装：`pkg/utils/certmanager/store/filestore_wrapper.go`
- Proxy Server：`pkg/proxyengine/proxyserver/proxyserver.go`
- 引擎调度：`pkg/engine/proxy.go`、`pkg/engine/engine.go`

引擎层 `proxyServerHandler` RestartType 路径：

```go
srcAddr := getSrcAddressForProxyServer(p.client, p.nodeName)
if strings.Join(p.serverLocalEndpoints, ",") != strings.Join(srcAddr, ",") {
    p.stopProxyServer()
    time.Sleep(2 * time.Second)
    err := p.startProxyServer()
    ...
}
```

`getSrcAddressForProxyServer` 只收集 `aep.NodeName == nodeName` 的 PublicIP；而 commit `91f6cab` 后证书 SAN 已扩到本 Gateway **所有** Proxy ActiveEndpoint 的 PublicIP。两者口径不一致。

`pkg/utils/certmanager/store/filestore_wrapper.go` 已经把任何加载错误转成 `NoCertKeyError`，cert manager 收到这个错误就会重新发起 CSR。也就是“证书不在 → 自动重建”这条路径已经存在，可以直接利用。

## 2. 现有问题

### 2.1 重启触发条件比 SAN 计算窄

`getSrcAddressForProxyServer` 只看本节点的 ActiveEndpoint。当本 Gateway 内**其他节点**的 Proxy ActiveEndpoint.PublicIP 变化时：

- 证书 SAN 的“期望集合”应当包含新 PublicIP（来自 `getProxyServerIPsAndDNSName`）
- 但 `serverLocalEndpoints` 的对比项没变 → 不重启 → 证书 SAN 仍是旧值

这是当前的核心 bug。

### 2.2 证书 SAN 不刷新没有兜底

哪怕引擎重启 ProxyServer，启动时 cert manager 看到磁盘上已有有效证书且未到期，会优先沿用它。是否会因为 SAN 不匹配立刻轮换，依赖 `client-go` 的 `dynamicTemplate` 实现细节，跨版本行为可能漂。如果能在重启时显式让证书“缺失”，则下次启动一定走重新签发路径，确定性更强。

## 3. 目标 & 非目标

### 3.1 目标

1. 当本 Gateway 的 Proxy ActiveEndpoint **PublicIP 集合**（不区分节点）发生变化时，重启 ProxyServer。
2. ProxyServer 重启后必然以新 SAN 重新签发服务端证书，不依赖 cert manager 内部探测路径。
3. 改动尽量小：复用既有的“证书缺失 → NoCertKeyError → 重新 CSR”链路，不引入新的解析器/fingerprint 抽象。

### 3.2 非目标

- 不做证书的“in-place 热替”。
- 不修改 signer / CSR 链路 / RBAC。
- 不动 Tunnel（L4）证书、不动 proxy client 证书。
- 不把 Service 类 SAN 来源（ClusterIP / LB ingress / 注解）作为重启条件——它们极少变；ProxyServer 生命周期内仍由 `dynamicTemplate` 顺手处理。

## 4. 设计

### 4.1 总体思路

两点改动：

**A. 重启触发条件改为“PublicIP 集合变化”**

不再比较 `serverLocalEndpoints`（只含本节点），改为比较“本 Gateway 中所有 `Type=Proxy && PublicIP != ""` 的 PublicIP 排序去重集合”。这与证书 SAN 中“Gateway 部分”的来源完全一致，杜绝触发条件与 SAN 之间的覆盖差。

**B. 停止 ProxyServer 时删除服务端证书**

在 `stopProxyServer` 之后、下一次 `startProxyServer` 之前，把磁盘上服务端证书相关文件删掉（仅服务端，不动 proxy user cert）。下次启动时：

- `serverCertMgr` 调 `fileStore.Current()` → 文件不在 → `fileStoreWrapper` 返回 `NoCertKeyError`
- cert manager 立刻调 `getTemplate()` → 用新 ProxyServer 实例的 Gateway 快照算出新 SAN → 提交 CSR
- 签发完成 → 新证书落盘 → ProxyServer 通过 `wait.PollUntilContextCancel` 等到 `Current() != nil` 后继续启动 listener

整条路径走的全是已有逻辑，新增只是一次文件删除。

### 4.2 关键改动

#### 4.2.1 引入 PublicIP 集合 helper

`pkg/engine/proxy.go`：

```go
// collectGatewayProxyPublicIPs 返回 gw 中所有 Type=Proxy 且 PublicIP 非空的
// PublicIP 集合，去重并排序。用于判定 ProxyServer 是否需要重启。
//
// 与证书 SAN 中“Gateway 部分”使用同一份过滤逻辑（pkg/proxyengine/proxyserver
// 的 getProxyServerIPsAndDNSName 中关于 ActiveEndpoints 的部分），确保
// 触发条件与 SAN 输入一致。
func collectGatewayProxyPublicIPs(gw *v1beta1.Gateway) []string {
    if gw == nil {
        return nil
    }
    set := make(map[string]struct{})
    for _, aep := range gw.Status.ActiveEndpoints {
        if aep == nil || aep.Type != v1beta1.Proxy || aep.PublicIP == "" {
            continue
        }
        set[aep.PublicIP] = struct{}{}
    }
    out := make([]string, 0, len(set))
    for ip := range set {
        out = append(out, ip)
    }
    sort.Strings(out)
    return out
}
```

#### 4.2.2 引入证书清理 helper

`pkg/utils/certmanager/store/filestore_wrapper.go`（同包就近放）：

```go
// PurgeCert removes cert/key files associated with pairNamePrefix in
// certDirectory. After purge, the next certificate.Manager loading from
// this directory will see a missing certificate (NoCertKeyError via the
// fileStoreWrapper) and trigger a fresh CSR using its current GetTemplate.
//
// Returns nil if files are already absent. Other I/O errors are returned
// to the caller, which should typically log and proceed (the cert manager
// will still try to re-issue if loading fails for any reason).
func PurgeCert(certDirectory, pairNamePrefix string) error {
    pattern := filepath.Join(certDirectory, pairNamePrefix+"-*")
    matches, err := filepath.Glob(pattern)
    if err != nil {
        return fmt.Errorf("glob cert files for %q: %w", pairNamePrefix, err)
    }
    for _, p := range matches {
        if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
            return fmt.Errorf("remove %q: %w", p, err)
        }
    }
    return nil
}
```

> k8s `certificate.NewFileStore` 写入的文件名形如
> `<prefix>-current.pem` 与 `<prefix>-<unix-ts>.pem`，glob `<prefix>-*`
> 能完整覆盖。proxy user cert（`RavenProxyUserName` 前缀）与服务端 cert
> （`RavenProxyServerName` 前缀）共用同一 certDir，prefix 不同，不会
> 误删。

#### 4.2.3 修改 `proxyServerHandler`

`pkg/engine/proxy.go`：

```go
type ProxyEngine struct {
    ...
    // serverPublicIPs 记录上一次启动 ProxyServer 时 Gateway 的 Proxy
    // PublicIP 集合，用于判定是否需要重启。
    serverPublicIPs []string
}

func (p *ProxyEngine) proxyServerHandler(enableServer bool) error {
    switch JudgeAction(p.proxyOption.GetServerStatus(), enableServer) {
    case StartType:
        if err := p.startProxyServer(); err != nil {
            return err
        }
        p.serverPublicIPs = collectGatewayProxyPublicIPs(p.localGateway)

    case StopType:
        p.stopProxyServer()
        p.purgeServerCert() // 见 4.2.4
        p.serverPublicIPs = nil

    case RestartType:
        curr := collectGatewayProxyPublicIPs(p.localGateway)
        if equalStringSlice(curr, p.serverPublicIPs) {
            return nil
        }
        klog.Infof("proxy server gateway public IPs changed: %v -> %v, restarting",
            p.serverPublicIPs, curr)
        p.stopProxyServer()
        p.purgeServerCert()
        time.Sleep(2 * time.Second)
        if err := p.startProxyServer(); err != nil {
            return err
        }
        p.serverPublicIPs = curr
    }
    return nil
}

func (p *ProxyEngine) purgeServerCert() {
    if err := store.PurgeCert(p.config.Proxy.ProxyServerCertDir, utils.RavenProxyServerName); err != nil {
        klog.Warningf("failed to purge proxy server cert (will rely on cert manager rotation): %v", err)
    }
}
```

注：

- `equalStringSlice` 是简单切片相等比较；两个集合都已排序，直接 `slices.Equal`/`reflect.DeepEqual` 即可。
- StopType 路径也清证书：当 ProxyServer 停止（节点不再担任 server），下次再启动时一定要新 SAN，不复用旧的。
- `getSrcAddressForProxyServer` 不再用作触发条件；本期保留函数（其他地方暂无引用，可以一并删，由 reviewer 决定）。`p.serverLocalEndpoints` 字段一并删除以避免双 source-of-truth。

#### 4.2.4 ProxyServer 自身不变

`pkg/proxyengine/proxyserver/proxyserver.go` 不动：

- `IPGetter / DNSGetter` 仍然走 `getProxyServerIPsAndDNSName`，使用本生命周期内的 Gateway 快照（DeepCopy）。
- 因为引擎已经在重启时删证书并喂入新快照，IPGetter 在新 ProxyServer 实例第一次被调用（CSR 触发）时拿到的就是新 SAN。
- 这一点保持现状，**改动面只在引擎和新增 helper**。

### 4.3 时序

```
controller-manager 写入 Gateway.Status.ActiveEndpoints[*].PublicIP=newIP
        │
        ▼
informer cache 更新；engine watch 入队
        │
        ▼
engine.sync → findLocalGateway → p.localGateway = newGw
        │
        ▼
proxyServerHandler RestartType:
    curr  = collectGatewayProxyPublicIPs(newGw)        // {newIP, ...}
    prev  = p.serverPublicIPs                          // {oldIP, ...}
    curr ≠ prev
        │
        ▼
stopProxyServer (cancel ctx)
        │
        ▼
purgeServerCert
    rm <ProxyServerCertDir>/raven-proxy-server-*
        │
        ▼   sleep 2s
        ▼
startProxyServer:
    NewProxyServer(... newGw.DeepCopy())
    factory.New(serverCertCfg) → certificate.Manager.Start()
      └─ FileStore.Current() → file 不存在 → NoCertKeyError
      └─ getTemplate() → IPGetter → 新 SAN
      └─ submit CSR → kubelet-serving signer → approved
      └─ FileStore 写入新证书
    PollUntilContextCancel 等到 Current() != nil
    runServers() 拉起 ANP / agent / master / metrics
        │
        ▼
远端 raven-agent 重连新 PublicIP，TLS 用新证书握手
```

### 4.4 边界条件

| 场景 | 处理 |
|---|---|
| `findLocalGateway` 失败 | `localGateway` 保留旧值（已是当前行为）→ `serverPublicIPs` 比较结果不变 → 不重启 |
| Gateway 被删 | `localGateway = nil` → JudgeAction 走 StopType → 清证书、清 serverPublicIPs |
| 新 Gateway 还没 ActiveEndpoint | `curr = []`；首次 StartType 时记录为空集；后面有 IP 写入即触发一次重启 |
| `purgeServerCert` 失败 | 仅打 warning；启动时若证书 SAN 不匹配，cert manager 的 `dynamicTemplate` 兜底会触发轮换；不影响最终一致性 |
| ActiveEndpoint 短时间频繁切换 | 每次都重启；属于上游问题。本期不加冷却，未来可加最小重启间隔 |
| 多个 raven-server 副本 | 每个副本独立判定、独立重启，互不影响 |
| 仅 Service ClusterIP / LB ingress 变化 | 不进入重启路径；ProxyServer 生命周期内由 `dynamicTemplate` 顺手轮换证书（保留现状） |

### 4.5 兼容性

- API / CRD / flag 不变。
- Helm / RBAC 不变。
- 升级：旧证书在升级后仍可用；下一次 PublicIP 变化时新逻辑接管。
- 回滚：恢复旧 `proxyServerHandler` 字符串数组比较即可；磁盘上证书与旧版兼容。

## 5. 风险

1. **`PurgeCert` glob 匹配错文件**：限定 `<prefix>-*`，prefix 之间不会互相吃。新增组件 cert 时只要 prefix 不撞就安全。单测覆盖。
2. **purge 失败导致仍用旧证书**：靠 `dynamicTemplate` 兜底。最坏情况是“没有显式 deterministic”，但结果仍最终一致。日志能看到 warning。
3. **`stopProxyServer` 与 `purgeServerCert` 之间的并发**：`stopProxyServer` 取消 ctx 后 cert manager goroutine 退出，但写盘可能尚在飞。purge 在它后面执行，会删掉刚写入的文件，等价于“此次轮换被作废”。下次启动一定走重新签发，最终状态正确。
4. **2s sleep 与现有行为一致**，不引入新风险。

## 6. 实施计划

### Phase 1 —— 加 `PurgeCert`

- 新增 `pkg/utils/certmanager/store/filestore_wrapper.go` 中的 `PurgeCert`（或拆 `purge.go`）
- 单测：
  - 已有 `<prefix>-current.pem` + `<prefix>-<ts>.pem` → 全部删除
  - 不同 prefix 的文件保留
  - 文件不存在 → 返回 nil
  - certDir 不存在 → 返回 nil（glob 不报错）

### Phase 2 —— 改 `proxyServerHandler`

- 新增 `collectGatewayProxyPublicIPs`、helper `equalStringSlice`
- `ProxyEngine` 字段：`serverLocalEndpoints` → `serverPublicIPs`
- StartType / StopType / RestartType 三条路径按 4.2.3 改写
- `purgeServerCert` 包装 `store.PurgeCert`，warning 日志
- 删除 `getSrcAddressForProxyServer` 与 `serverLocalEndpoints`（如 reviewer 倾向保守可只灰化）

### Phase 3 —— 验证

- `go test -race ./...` 全绿
- 手动 e2e：
  1. ExposeType=PublicIP，patch 本节点 ActiveEndpoint.PublicIP → 观察重启日志、cert dir 中文件被删后重建、新证书 SAN 含新 IP
  2. patch 同 Gateway 内**非本节点** ActiveEndpoint.PublicIP → 同样重启（修复当前覆盖差，是本期核心场景）
  3. `kubectl delete gateway` → 走 StopType；cert dir 中服务端证书被清除；proxy user 证书保留
  4. ExposeType 由非空变空 → StopType 触发，不进 RestartType

## 7. 测试计划

### 7.1 单测 `pkg/utils/certmanager/store/filestore_wrapper_test.go`（扩展）

- `PurgeCert` 用例如 Phase 1 列出
- 强制使用 `t.TempDir()` 隔离

### 7.2 单测 `pkg/engine/proxy_test.go`（扩展）

- `collectGatewayProxyPublicIPs`：
  - nil Gateway → nil
  - 多个 ActiveEndpoint，混入非 Proxy / 空 PublicIP → 只保留 Proxy 非空、去重排序
  - 顺序无关，输出稳定
- `proxyServerHandler` 行为（mock 化 startProxyServer / stopProxyServer）：
  - StartType：调一次 start，记录 serverPublicIPs
  - StopType：调一次 stop + purge，清空 serverPublicIPs
  - RestartType + PublicIPs 不变 → 不调 stop/start/purge
  - RestartType + PublicIPs 变化 → 调 stop + purge + start
  - RestartType + 非本节点 PublicIP 变化（覆盖差用例）→ 同样触发

### 7.3 手动 e2e

如 Phase 3 描述。

## 8. 待决问题

1. 是否给重启加 metric `raven_proxy_server_restart_total{reason="public_ip_change"}`？建议加，便于排查。
2. 是否保留 `getSrcAddressForProxyServer` / `serverLocalEndpoints`？倾向删除，避免 dead code 与误用。请 reviewer 拍板。
3. 是否需要最小重启间隔（防止 PublicIP 抖动导致重启风暴）？倾向先不加，观察生产数据。

## 9. 参考

- `pkg/proxyengine/proxyserver/proxyserver.go`
- `pkg/utils/certmanager/factory/factory.go`
- `pkg/utils/certmanager/store/filestore_wrapper.go`（已有的 `NoCertKeyError` 路径）
- `pkg/engine/proxy.go`、`pkg/engine/engine.go`
- commit `91f6cab` (include Gateway proxy ActiveEndpoint publicIPs in proxy server cert SAN)
- v1 / v2 设计（已废弃）：参见本文件 git 历史
