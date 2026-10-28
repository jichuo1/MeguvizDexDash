# MeguvizDexDash 架构决策与依赖选择

本文件给出默认实施方向与改变条件。状态 `proposed_default` 表示工程包建议按此启动，不表示相关实现已经验证。执行者在 M0 以实际构建与语义结果形成正式 ADR。

## 1 决策登记

| ADR | 默认决策 | 状态 | 必须验证／改变条件 |
| --- | --- | --- | --- |
| ADR-001 | Rust stable 核心，独立 worker；C ABI 与 Python 客户端分层 | proposed_default | 两个 Tier1 平台构建、依赖和异常边界；已有可复用实现的成本证据 |
| ADR-002 | typed IR 快速路径，SQLite 只读 virtual-table 兼容桥 | proposed_default | 真实 HostLab corpus、字符串/NULL/转换/排序语义；失败则更换 bridge 或补 profile，保持 IR 边界 |
| ADR-003 | 先结构化 JSON 批，再比较列批；禁止机器表格/hex | proposed_default | 完整编码→传输→消费、背压、精度及大小；不只测解码 |
| ADR-004 | 首版 own/private 输入快照，条件满足后 mmap | proposed_default | 来源改写／替换／关闭／并发与字节证据一致性 |
| ADR-005 | 自有 reader 可独立启动；AOSP 差分；DexMeguviz provider 可选 | proposed_default | provider 格式/语义、许可证、跨平台、升级与 oracle 独立性 |
| ADR-006 | 原始事实不可变，session TEMP 目录独立且代次化 | proposed_default | native 冻结 cursor、兼容 offset 重执行、目录与生命周期竞态 |
| ADR-007 | 事实缓存与业务结果缓存分层 | proposed_default | 全内容身份、schema/profile/规则键、崩溃与失效；负缓存完整性 |
| ADR-008 | Linux/Windows x86_64 先发布，macOS arm64 随后验证 | proposed_default | 对应原生环境运行，不以交叉编译代替 |
| ADR-009 | HostLab rules 作为 adapter，不进入核心 | proposed_default | 第二个无 BIL 依赖消费者、crate 依赖边界 |
| ADR-010 | GUI 在 engine/HostLab 资格后复用 SDK | proposed_default | 桌面平台打包、UI 响应、隔离和离线工作流 |
| ADR-011 | 对最佳现成路径验证新增收益，保留 A0 历史目标 | proposed_default | 固定 paired workload、独立复测、正确性与资源限制 |

## 2 为什么不同时自写所有基础设施

用户目标是拥有可复用的 DEX 分析软件与高效运行路径，并不要求重复编写压缩器、通用 SQL 数据库、TLS、窗口系统或所有基础容器。自研价值集中在输入与事实的语义、查询/索引策略、完整性、数据生命周期、批接口和业务适配。

成熟依赖可以使用，但它们不能定义核心的公开模型，也不能让未来切换 provider 需要改全部客户端。依赖版本与编译选项在锁文件、构建 manifest 和性能结果中记录；库升级需跑相关 conformance。

## 3 依赖选型方式

| 类别 | 初始候选或方式 | 不接受的替代验证 |
| --- | --- | --- |
| ZIP/DEFLATE | 维护活跃、支持所需 ZIP 特性的库；基于格式语料选择 | 只用几个正常 APK 成功便宣称 ZIP64/重复成员等全面支持 |
| 内容身份 | 已审计 SHA256 实现；校验来源字节与 profile 键 | size/mtime 代替完整身份；CRC 当强内容身份 |
| SQL | 固定 SQLite + virtual table 边界；typed IR 为主 | 查询能解析等同结果等价；全量 ETL 后把装载成本排除 |
| JSON/序列化 | 成熟 JSON 库，64 位整数与 UTF16 异常值有明确表示 | 默认浮点数丢精度；有损字符串替换 |
| CLI/日志 | 可维护参数解析与结构化日志 | 日志混入机器 stdout 导致协议破坏 |
| 并行 | 一层受预算线程执行；嵌套工作共享预算 | 每层单独开满 CPU 并将额外资源当算法提速 |
| mmap | 原始 bytes 抽象下的可选存储 provider | mmap 视作免费解压或不可变证明 |
| UI | 复用 SDK 的轻量桌面壳，默认可评估 Rust/WebView | UI 内另写查询/解析器或先做漂亮空壳 |
| 反编译 | JADX 可选 provider | 用 Java 输出替代精确原始代码或可证明 xref |

不得在工程包中随意指定未经当前平台构建验证的最新版号。M0 获取实际工具链和依赖，选择可支持所需格式与平台的固定版本，并保存 Cargo.lock、工具链文件和必要原生依赖构建参数。

## 4 SQL 桥的具体资格

SQLite virtual-table 官方接口允许以回调访问外部数据，并由 `xBestIndex` 声明可用约束和成本；这是实施桥的基础，不能自动等价 DexSQL。[官方文档](https://www.sqlite.org/vtab.html)

首先以保守扫描和正确 SQL 语义通过 corpus。随后逐条启用索引与列裁剪；只对确实已处理的过滤设置 omit，只对确实满足的顺序设置 orderByConsumed。LIKE 作为候选筛选时保留精确二次判断。可选 TEMP 目录在 session 内，不允许更改不可变源事实。

每个 profile 记录允许语句、函数、类型转换、比较、NULL、排序、临时对象和错误语义。准备一个 query 能成功不意味着 profile 已 admitted。真实 HostLab 必需集合必须全部完成，才能给 `hostlab-audit-v1` 资格；更多公开语句按兼容 profile 逐项扩展。

若真实 corpus 或 MUTF-8/NUL/UTF16 行为不能通过桥完整表达，不得默默转换或返回截断值。可选择在该 profile 显式拒绝相关输入、定义 lossless typed 表示，或更换兼容实现；首版所承诺的 HostLab 样本必须实际通过。

## 5 与其他引擎共享实现的规则

共享的单位是可版本化的库、ABI 或事实 provider，不是互相读取另一个工程的内部源码目录。共享包由明确仓库或模块负责发布、测试与升级；两个项目都锁定可用版本。

provider 必须声明输入、输出 facts schema、格式版本、验证程度、线程与资源语义。数据进入核心后统一转换为本项目来源 ID 和完整性状态，不允许 provider 返回“成功”就跳过核心 coverage。

如果共享 parser 是产品实现的一部分，独立 oracle 需来自不同实现或可人工验证的 fixture。重复包装同一 reader 不增加证明强度。

## 6 缓存与快照的选择记录

允许 source bytes 物理去重，但 occurrence 和逻辑 DEX 身份保持独立。缓存内容优先按完整物理容器验证，041 共享区间不得被误切成独立可复用的小文件。

完整事实、按需事实和结果缓存应分别标记 schema/coverage。没有完成的建立任务不能发布成有效缓存；崩溃时写入 staging 后原子提交，打开时验证身份与完整目录。并发 reader 的 lease 与删除/迁移的作用范围写入生命周期测试。

请求缓存记录参数、profile、rules/config、source/fact identity、catalog epoch 与结果完整性。具有不确定顺序、可变 TEMP 或未定义函数行为的 raw SQL 默认不进入完成结果缓存，直到有明确依赖策略。

## 7 调整方案的最小证据

改变语言、SQL 引擎、wire 编码、内存布局、缓存策略或 provider 时，ADR 至少保存：问题与观测、可复现基线、候选实现、完整语义结果、资源与耗时、失败或未选方案、迁移影响、决策及验证范围。

不因某一条最好看的微基准更换全部架构；也不因已有方案暂时不快就修改同工作量定义。已经能够保留的 SDK、输入身份、事实与验证成果应继续复用。
