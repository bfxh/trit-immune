# PR: Add trit-immune — 三进制安全裁决 + 免疫系统内核

## 一句话

在 bfxh/trit 的 K3 三值逻辑基础上，构建 **DeltaDB 式免疫网络**：因果 DAG + 合并门禁 +
自动淘汰 + 跨副本同步 + 设计决策生产线。trit 提供三进制原语，trit-immune 提供安全裁决域。

## 为什么放这个工作区

trit 提供了三值逻辑的全部原语（K3/Ł3/B3、双导轨位平面、TernaryTopology 可达性），
但缺少一个**安全裁决域**——把扫描器告警、红队结果、设计决策统一用三值标注并在因果
DAG 上传播。trit-immune 就是那个域层。它是 trit-core `Ternary` 的消费者，不是竞品。

## 映射

| trit 原语 | trit-immune 用法 |
|-----------|-----------------|
| `Ternary` (K3) | `Trit`（Vulnerable=-1 / Unknown=0 / Hardened=+1） |
| `TernaryTopology` 可达性 max∘min | `Contagion` 传播 min∘max（极性对偶） |
| 双导轨位平面 | `bitparallel.rs` TriWord（32 trit / u64 对） |
| 真值表穷举 | 门禁/传播/合并的一致性对拍 |
| `trit-policy` | `policy.rs` 合并策略引擎 |
| `trit-schedule` | `scheduler.rs` 有界 drain |

## 内容

| 模块 | 功能 | 测试 |
|------|------|------|
| `trit` | K3 全连接词 + Ł3 蕴含 | 真值表全 9 组合对拍 |
| `dag`/`verdict` | 因果 DAG + 合并门禁 ALLOW/FREEZE/BLOCK | 门禁三态/兄弟分支不殃及 |
| `sandbox` | 确定性沙盒替身 | 模糊测试升级 0 态 |
| `delta`/`journal` | 追加式日志 + HLC 时间戳 + 快照缓存 + 格式迁移 | 重放一致/损坏检测/v1→v2 |
| `propagate` | (min,max) 半环传播（TernaryTopology 极性对偶） | 81 种边值组合穷举 |
| `scan` | 静态扫描校准（Dispositive→-1 / Heuristic→0 / **永不 +1**） | 多语言全过管线 |
| `design` | 设计决策生产线（不审代码审决策） | 分类矩阵/SLA 默认通过 |
| `adoption` | 落地状态机（六态+变更包+依赖图精准推送） | 六态快乐路径/大降级/小自动 |
| `scheduler` | 有界劳动（drain_plan + worker 池 + 固定点收敛） | 恰好一次/固定点 |
| `lifecycle` | 统一生命周期 DAG（替代 5 个独立状态机） | 门禁/回滚/并行轨道 |
| `auth` | HMAC-SHA256（NIST/RFC 向量对拍） | 篡改拒绝/错钥拒绝 |
| `cull` | 自动淘汰（慢性漏洞隔离/僵化未知升级） | 慢性/阈值/不误伤 |
| `fleet` | 多仓舰队 + 跨仓污染边 + 聚合渲染 | 6 副本收敛/跨仓传染 |
| `server` | 本地 HTTP（tri/scan/diag/taskbar/intake/lsp） | 端点/并发/隔离 |
| `taskmd` | MD → 任务栏（打勾≠+1） | 幂等/隔离/固定点 |
| `intake` | 死依赖检测 + 自动管线 | 死依赖/端到端 |
| `migrate` | 日志格式迁移（v1→v2 原子替换+备份+校验） | 迁移/恢复/拒绝 |
| `transport` | 传输抽象（TCP/Memory/可插拔 TLS） | 确定性收敛 |

## 压力测试

千节点 DAG、万级日志重放、6 副本跨仓传播、100 节点级联回滚、1000 概念台账同构、
全管线端到端、并发 HTTP 100 请求——全部通过。

## 设计决策

- 零依赖（可选 `tls` feature 加 rustls）
- 扫描器永不产生 `+1`（没有证据不放行）
- 新代码默认 `0`（未测即不可信）
- 自动淘汰 ≠ 删除（状态跃迁，不丢数据）
- 门禁 = 因果链 + 传播后有效裁决的 K3 AND 折叠

## 许可

MIT OR Apache-2.0（与工作区一致）
