# MDD-026 索引与覆盖门禁

当前限定结论：不可变选定输入范围内的原生事实索引与 coverage 已实现并经过实际小型验证；不签 SQL、HostLab 替代、G1、ART 或性能资格。主代理负责将本目录与独立 `conformance/facts/` 的证据合并后决定任务终态。

实际重现命令：

```powershell
& 'C:\Users\Administrator\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -O artifacts/mdd-026/indexes/reproduce.py
```

每次运行创建新的 `runs/<UTC>/`。当前首个完整收据是 `runs/20261028T141315875747Z/result.json`：Rust stable 1.99.0、Windows x86_64 MSVC，35 个 mdd-facts 单元测试和 4 个 compile-fail 文档测试通过，严格 Clippy 通过。索引相关共 11 个测试。Python 在 `-O` 下通过，219 个 UTF16 equal/prefix/contains 请求逐项等于独立手工字符串池期望，包含 55 个候选存在假阳性、残余谓词剔除后的正确请求；两个相同内容的输入出现次数不合并。156 列的名称、类型、NULL 和投影状态与独立完整矩阵逐列一致。原始 stdout/stderr、每条命令、退出码、SHA256、工具链、当前锁文件及全部自有源文件摘要都保留。

离线回读命令 `python -O artifacts/mdd-026/indexes/verify.py` 也已实际通过：核对十份 stdout/stderr 摘要、零退出码、原始输出与解析后 JSON 同一性、当前源码/lock/手工期望与矩阵身份；六个人为损坏的结果、来源、重复 occurrence、缺页与列声明控制均被拒绝。见同目录 `readback.json`，另记录实际测试二进制的长度与 SHA256。该身份观察不升级任何平台或产品资格。

## 公共入口与范围

- `SelectedScope::from_inventories(snapshot, inventories)` 封闭构造同一 Snapshot 的显式输入子集，验证所有成员的来源与内容身份，保持 Snapshot 输入顺序、选定 DEX 顺序和每个 logical occurrence。`file_id` 是该显式选定范围内的零基顺序，不能在不同 scope 间裸连接。物理相同内容仍有不同 occurrence。scope 自身持有捕获字节 lease，不重开路径。
- `SelectedScope::pending` 表示尚无成员清点证明，DEX roster 为 Unknown；不能把它当已证实零 DEX。显式完整子集可以 Complete，但报告与负证据明确 `covers_all_captured_sources=false`。
- `FactView` 只借用已封闭的 Metadata/Definitions/Code/Annotations/References/RawCode 事实；构建 ledger/index 时逐个验证同一 snapshot、DEX occurrence、member、source occurrence 和内容身份。
- `SnapshotFactIndex` 按需建立字符串、定义/owner 和 encoded method-symbol 引用候选索引。字符串以 UTF16 code units 做精确/前缀/包含匹配，MUTF8 raw 单独查询；包含候选只用首 code unit 召回，所有候选再做精确残余过滤。定义的 class_def_idx 与 type_idx 分开。引用复用已有 ReferenceFacts 逐 operand/site 索引；symbol 全扫参考路径不读取懒索引，不把 encoded target 当动态运行时目标。
- `IndexMatches` 和 `ReferenceIndexMatches` 保留 scope、coverage、访问路径、候选数、审计与限定负证据；空结果只能在必需范围已 Complete 时返回。各来源同 owner 的定义与引用站点均不去重。

## 惰性建立与预算

`LazyIndex` 每个实例/attempt 有独立身份和单一终态。首次并发调用只执行一次 producer，四个实际等待者共享 Ready；失败没有隐式重试，显式 retry 创建新 attempt。实际并发测试加确定性的 late-wake 状态反例证明：已加入 attempt 1 的等待者在 attempt 2 Ready 后仍得到 attempt 1 的真实错误。producer panic 成为 InternalFault，不变 unsupported；quota、deadline 原错误和各次终态保留；超过尝试次数不执行 producer。

候选采用借用迭代，实体与跨来源站点输出在继续复制前检查数量/估算字节配额。索引建立按项检查数量、估算字节和协作 deadline。这里的字节预算是结构成本计费，不能替代操作系统内存硬上限；不宣称 allocation/OOM 或 abort 可由 Rust panic 捕获。后续全请求预算/取消仍由 MDD-034 承担。

## coverage 语义与反例

`CoverageLedger::evaluate` 根据 `scope_id`、输入要求、必需层、具体列和资源成员重新计算 input/facts 的 Complete/Partial/Unknown。必需层与其依赖的全部失败都保留；聚合时 Partial 优先 Unknown，原始真实错误优先于三种 fallback 错误。根审计的三个反例均有实际测试：前置 Definitions Unknown 加后续 AllMethodBodies InvalidInput 仍返回原 InvalidInput；输入 Unsupported 在先也不能掩盖必需事实 InvalidInput；同键记录第二个终态被拒绝，不能用后写 Unsupported 覆盖既有损坏。空 roster/零结果不能绕过输入损坏。

粒度独立：指定 code projection 的完成不表示所有 physical code 或所有定义方法体完成；参数已编码 slots Complete 不表示所有 prototype 位置已证实，缺失位置为 Unknown；源码位置未构建为 Unknown；未建立资源 raw bytes 不当作零资源。无关注解消费者失败不污染只要求 references 的正确独立范围。

`ColumnDomain::NativeAtoms` 表示可由已验证的原生原子无损获得该列；`FrozenProjection` 还要求现成关系装配与精确列门禁。完整矩阵为 17 关系 156 列，其中 69 列尚未装配成兼容关系。它们请求 FrozenProjection 会明确列名并 Unknown/IncompleteFacts；不填 NULL、不用 insns_size 代替 opcode_count、不对孤立代理做 UTF8 替换。所有产品 profile 维持 false。独立跨层验证及这些装配边界见 `conformance/facts/required-columns.json`、`artifacts/mdd-026/facts-differential.json`。

## 验收与回滚

1. 候选召回与残余：手工 fixture、219 个独立 Python 期望、标量路径、owner 手工计数与完整引用站点核验通过。
2. 懒构建、并发、重试：三个实际并发/异常测试和真实 quota/deadline 失败记录通过。
3. 三态、scope 和必需层失败门禁：原错优先、失败不可覆盖、子集负证据与细分层测试通过。
4. 必需事实各列语义：本模块声明与独立 156 列矩阵全等；完整层间字段/NULL/顺序/重复/来源/raw 指纹证据由独立负责人产出，不将 69 个兼容投影缺口假装已交付。
5. 独立核验：独立手工字符串池 Python oracle 通过，独立负责人另有 8 场景/9 DEX、331 target、43 个全 schema 关系比较，根需按实际源码复验合并。

保留开发期失败 `runs/first-runnable.txt`、`runs/first-clippy.txt` 及 `development-failures.json`，未修改既有 fixture golden 迎合实现。当前没有私有大解析或性能运行。需要回滚时，由主代理在审查分支对本范围创建普通 revert，保留失败收据；不 reset/clean/强推，不改变既有事实模块或共享状态文件。
