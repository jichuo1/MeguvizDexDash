# ADR-002：以只读 SQLite 虚表桥验证兼容语义

- 状态：accepted（M0 有限路线实验与实现边界）；所有 SQL/profile 资格仍未准入。
- 日期、作者、关联任务：2026-10-28，查询/传输代理，MDD-006。
- 替代/被替代：无；落实工程包 ADR-002 默认方案。
- 范围：固定版本 SQLite 的未来 Rust 桥；HostLab 必需 profile 与公开兼容 profile 分开。

## 背景与约束

工程包含真实查询类别、历史行为观察和协议设计。此次已在 Windows x86_64 构建 Rust 只读虚表探针，以 Arc 持有合成不可变行，实际运行代表性查询和反例。MDD-006 是有限路线实验/契约决策任务；完整查询实现和 HostLab profile 资格继续由后续任务验收。

## 决策

沿用 typed IR 和不可变事实作为核心；SQL 桥仅是前端，不拥有事实，不默认全量 ETL。用户已批准 rusqlite 0.40.2；本次实际捆绑 SQLite 3.53.2，源码身份和构建选项由 MDD-002 记录并由 Cargo.lock 固定。当前没有已准入 SQL 方言。

虚表最初使用完整扫描，`omit=false`、`orderByConsumed=false`，不下推 LIMIT/OFFSET。`xBestIndex` 仅报告成本，不在优化器试探时建立昂贵事实。只读事实不实现 xUpdate，实际 DELETE 被 SQLite 拒绝。生产桥须使用 authorizer、defensive 配置和语句级能力控制禁止 ATTACH、load_extension、文件访问扩展和未承诺 PRAGMA。实际 compile_options 包含 ENABLE_LOAD_EXTENSION；关闭 rusqlite 扩展 API feature 不等于 C 库编译期移除该能力，当前探针也不代表生产安全边界已经实现。

DEX 文本保留原 MUTF-8 与 UTF-16 code units，JSON 采用带类型的无损值；原字节列使用 dex_mutf8 标签和长度，展示字段另外命名。标量 Unicode 展示与原值分列；禁止把孤立代理替换后用于比较、CAST 或指纹。SQLite 默认 TEXT/LIKE/length 不能直接成为 DexSQL 兼容语义。

桥实现必须显式维护原始字节和列类型，针对长度、LIKE 和 UTF-16 排序提供版本化 UDF/collation；CAST、literal 和表达式传播需要经过 AST 处理或等价的已证明 typed 计划适配，禁止正则改写。无法无损表达的输入先明确拒绝该未准入 SQL profile，原生 typed facts 保留原值；必需 HostLab 输入被拒绝时该 profile 继续不能获准，不能通过拒绝输入缩小资格分母。

TEMP 对象按方言保存查询定义及依赖图，避免以物化 SQLite TEMP 表冒充该契约。目录更新增加十进制 u64 catalog_epoch；prepare 固定旧目录，新 prepare 才读取新目录。原生 cursor 与兼容 OFFSET 重执行分别声明。

## 候选与取舍

1. SQLite 虚表是初始候选，优势是可复用 SQL 解析和执行；代价是 CAST、MUTF-8、NUL、LIKE、字符串 literal 和 TEMP 仍需独立适配。
2. 以类型化请求迁移高频查询，减少字符串 SQL 接口成本；不能因此删掉必需 SQL 的验证分母。
3. 若 SQLite 无法完整表达必需查询，另选兼容执行器，保留 facts/IR/快照边界；不先重写完整通用 SQL 引擎。

## 验证与退出条件

执行真实 corpus 的 NULL/空值、i64/u64、CASE/CAST/hex、LIKE `_` 与 ESCAPE、大小写/NUL、UTF-16 排序、重复投影列、JOIN/COUNT/DISTINCT/GROUP、CTE/子查询、IN/BETWEEN、LIMIT/OFFSET。每个必需模板须有实际完全展开 SQL、真实数据、完整类型和 bag/ordered 证书。

TEMP 测试包括 late bind、重定义、DROP、IF NOT EXISTS、循环、跨 session 隔离、旧 cursor 与新目录。强制比较 full-scan 与优化路径；只在反例与全部对应语义均通过后设置 omit/orderByConsumed。禁止正则改写 SQL。

任一必需表达式失败，则 HostLab profile 保持 admitted=false。记录原始错误，不能将解析错误伪装 unsupported；不得靠整程 fallback 签发替代资格。

本次有限实验实际确认 NUL length 截止、默认 `_` 通配、UTF-8 BINARY/UTF-16 顺序差异、孤立代理 TEXT 与 TEMP CTAS 物化五类缺口。它们阻止兼容资格，未推翻只读虚表作为候选前端的可行性。MDD-031 必须先实现必要适配并重跑完整 corpus；若仍有必需表达式无法表达，启动替代执行器 ADR 并保持 facts/IR 边界。不能将本 ADR 的接受状态解释为完整桥或替代资格完成。

## 迁移与回滚

SQL 方言和工作流 profile 独立。保留旧 DexSQL 身份与安装器，新桥将使用 meguvizdexdash backend。未通过资格的桥保持未启用；撤回候选入口不改变现有 HostLab 默认配置。

## 证据

- 设计依据：`docs/02_ARCHITECTURE_AND_CONTRACTS.md` 第 6 节、`docs/03_HOSTLAB_MIGRATION.md` 第 5 节、`docs/04_VALIDATION_AND_PERFORMANCE.md` 第 8 节。
- 实际代码：`tools/build-probe/src/sql.rs`；此开发探针含合成事实，未解析生产 DEX。
- 首轮实际输出：`artifacts/mdd-006/rust-sql-probe/stdout.txt` 与同目录 record.json；后续冻结 corpus 原样运行保留独立目录。
- 当前提取与身份：`artifacts/mdd-006/sql-bridge-probes.json`；逐项任务验收：`artifacts/mdd-006/acceptance-review.json`。
