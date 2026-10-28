# MeguvizDexDash：开发执行与交接手册

规格版本：0.1-draft。本文落实 [主计划](../ENGINEERING_PLAN.md) 和 [AI 执行提示词](../AI_EXECUTION_PROMPT.md)，不新增任务图、错误枚举或性能门槛；技术规则见 [核心契约](02_ARCHITECTURE_AND_CONTRACTS.md)、[HostLab 迁移](03_HOSTLAB_MIGRATION.md) 和 [验证规范](04_VALIDATION_AND_PERFORMANCE.md)。

**当前包是规格、模板和历史证据，不是引擎。** 运行模块与命令须在对应阶段实现；列出命令不等于执行过。

## 1. 唯一事实入口

| 文件或目录 | 责任与更新规则 |
| --- | --- |
| `tasks/backlog.json` | 唯一任务图、依赖和实施状态；沿用 MDD 任务 ID，不再另列一套阶段编号 |
| `STATE.md` | 当前 checkout、工作进度、阻塞、负责人和下一动作；是恢复入口，不是测试数据库 |
| `docs/adr/` | 版本化决策；使用 `templates/ADR.template.md`，保留被替代决策及新 ADR 链接 |
| `compatibility/ledger.json` | 唯一兼容/能力资格账本；初始 planned，按格式、profile、平台和证据升级 |
| `evidence/index.json` | 冻结历史研究、测量及来源；不冒充当前新引擎测试 |
| `artifacts/index.json` | 实施后新增构建、验证和运行证据的索引；初始没有引擎成功运行 |
| `benchmarks/workloads/` | 预注册 workload、输入、分组、计时窗口与预算；`initial.json` 是设计定义 |
| `templates/EXPERIENCE_RECORD.template.md` | 六段经验记录模板；实例建议保存于 `docs/experience/` |

共享文件由指定集成者单写，其他代理提交补丁。路径变化须同步引用和验证器，不保留双重权威；历史观测只追加更正说明。

## 2. M0 首轮：先固定身份，再推进实现

### 2.1 检查工作区

先读当前用户指令和仓库约束，再检查已有文件和改动。工程与 HostLab 独立，必要时用隔离 worktree；不覆盖已有工程或清理他人改动。

下列为只读检查示例；在正确目录执行，某个工具不存在就记录缺失，不能编造版本：

```bash
git status --short
git rev-parse HEAD
rg --files -g AGENTS.md
rustc -Vv
cargo -V
python3 --version
```

Windows 使用实际解释器，如 `py -3`。日志只保留相关元数据，不导出环境凭据。

在工程包根目录，只有文件确实存在时运行：

```bash
python3 tools/verify_kit.py
python3 tools/recompute_targets.py
```

`verify_kit.py` 校验**交付包原始快照**，不是引擎 CI。实施后改任务/文档导致原 manifest 不匹配属正常变化；后续 CI 按阶段验证代码，重新打包才生成新 manifest，不能把原包 hash 当永恒门禁。`recompute_targets.py` 重算历史条件预算。两者均不执行或证明引擎测试。缺命令/失败须如实记录，不用退出 0 的占位脚本消除。

### 2.2 首轮应形成的文件

按 MDD-001～006 形成下表结果；细化路径服从 backlog 与契约，不另建任务图。

| 交付 | 最小内容 |
| --- | --- |
| 更新 `STATE.md` | 实际源码/分支、dirty 状态、工具是否可用、样本/二进制可用性、当前负责人和下一可执行任务 |
| `artifacts/bootstrap/<run_id>/environment.json` | OS/架构、CPU 配额、内存限制、工具/编译器版本、检查时间和命令结果 |
| 同目录 `source-manifest.json` | 本工程/HostLab commit，输入与 DexSQL 两版二进制摘要、来源和实际可用状态；不把研究 SHA 当实际 checkout |
| `conformance/` 下 profile/corpus 清单 | 真实 SQL 模板和动态参数类别、完整 schema/排序/多重性、工具分层、异常路径和独立 oracle |
| fixture manifest | 来源 URL/授权范围、生成方法、SHA、格式、预期状态、是否实际取得；私有样本仅登记引用 |
| 初始 ADR 和依赖锁定材料 | Rust、SQL 桥、wire、输入所有权等默认决策的验证计划和退出条件；已有结论不重做无关调研 |
| `benchmarks/workloads/` | A0/A1/A2 的同环境计划；B0/B1 尚无实现时明确不运行，不填虚拟成绩 |

私有 APK 缺失只阻塞相关完整验收，继续公共语料与独立工作；无 DexMeguviz provider 则推进自有 reader。M0 问题须有调查退出条件，满足当前依赖后继续 M1。

## 3. 固定语言、依赖与构建环境

默认 Rust stable；M0 实测后将**具体版本**写入 `rust-toolchain.toml`，声明 MSRV、targets、组件；浮动 `stable` 不构成固定构建。记录 Rust/Cargo、linker、SDK/原生工具链；首版平台为 Linux/Windows x86_64。

- 提交 workspace 的 `Cargo.lock`；CI/build 使用 `--locked`。依赖更新是独立变更，检查 lock diff、功能开关、许可与受影响 conformance，不在基准中途更新。
- Python 固定解释器与唯一锁文件/安装方式，使用独立环境；依赖 hash 如已锁定，安装必须验证。
- SQLite/AOSP/JADX 等原生或外部 provider 固定 tag/commit、源/包摘要、编译选项、patch 和 ABI。系统库与捆绑库是不同 build profile，不能未记录地混用。
- 构建 manifest 包括 Cargo features、优化/LTO、target CPU、环境限制及依赖身份。`target-cpu=native` 等机器相关设置不能在通用发行包中无声明启用。
- fuzz/sanitizer 如需另一工具链，单独固定；不因测试使用 nightly 而改动 stable 发布契约。具体检测范围按验证文档声明。
- 下载受限时记录缓存/镜像与 checksum，不关闭校验或替换未知二进制；继续独立工作。

升级影响 schema、IR、持久格式、行为 profile 或 provider 时，同时更新相应版本和失效规则；仅改 Cargo.lock 不能自动证明缓存兼容。

## 4. 日常开发循环与命令

### 4.1 一次可审查变更

领取依赖已满足的任务及写入范围，先明确输出/通过条件。阅读相关代码、契约和 regression，实现真实纵向能力并验证风险；检查 diff、证据和失败范围后才更新状态。

**以下 Cargo 命令仅在 M1 已创建真实 workspace、相关 crate 存在后可用，本轮没有执行：**

```bash
cargo metadata --locked --format-version 1 --no-deps
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release -p mdd-cli -p mdd-worker
```

先跑改动相关测试，再跑要求的集成 gate。所有 feature 组合以支持矩阵为准；不要机械使用 `--all-features` 迫使互斥 provider 同时启用，也不要只测默认 features 就称全部通过。

Python 测试目录和依赖真实存在后，可在锁定环境运行：

```bash
python3 -m pytest python/tests integrations/hostlab/tests
```

目标不存在则记未运行/受阻；不创建空测试、不用 `|| true` 或吞异常制造成功。零测试不能签发资格。

### 4.2 自定义验证命令的登记

M1 起在 `conformance/README.md`、`benchmarks/README.md` 和 CI 登记真实命令：版本、目录、参数、fixture、预期、证据与失败含义。不存在的命令不得记为已运行。

每次保存命令、源码/dirty diff、工具链、退出状态和日志；长任务加 PID/session 与进度。退出码不替代完整结果检查；失败先定位，不改 golden 迎合实现。

## 5. 多代理协作与测量独占

职责沿用主计划：格式/事实、查询/协议、HostLab 适配、独立验证；槽位不足按依赖分波次。主代理负责接口、优先级和最终集成，不要求每个子代理重复调研全部背景。

派工消息至少列：任务 ID、固定输入、输出路径、允许写入文件、禁止触碰范围、依赖、验收、需要的资源。共享 `Cargo.toml/Cargo.lock`、schema、STATE、backlog 和 ledger 指定单写者；跨模块接口先由主代理确认同一版本，再并行实现消费者。不能通过复制 parser/SQL 内核避免沟通。

worktree 记录 branch/commit 和集成基线；共享目录先交接写入权。集成者核对 diff、依赖与测试，不能凭子代理“完成”消息放行或覆盖他人改动。

**CPU 基准实行同机独占。**主代理登记测量者、主机、run ID、时间窗及预计结束；未来协调工具可在 `artifacts/coordination/` 保存带持有者的 lease。未实现工具前采用明确消息交接，不伪造锁文件保证。

独占期其他代理只做轻量阅读/文档；暂停编译、fuzz、另一个 benchmark、大规模 hash、下载/解压等会干扰 CPU、I/O 或页缓存的工作。测量者结束或失败后显式释放并通知下一位；异常遗留 lease 先确认实际进程状态，不能只看时间过期就并发开跑。此流程只降低已知干扰，不保证云主机没有噪声，环境记录仍须保存。

## 6. 任务状态与完成证据

任务只使用 `todo / in_progress / blocked / done`，字段格式服从 `tasks/backlog.json`；这是工程状态，不是产品结果 envelope 的错误枚举。

| 状态 | 进入条件 | 必须记录 |
| --- | --- | --- |
| `todo` | 未开始实现或尚未领取 | 已有输入、依赖、目标产物；历史研究不能算实现进度 |
| `in_progress` | 已领取且正在产出 | owner、branch/路径范围、开始时间、当前成果和下一动作 |
| `blocked` | 具体依赖/输入/runner/权限阻止该任务完成 | 缺什么、如何验证已恢复、谁/哪项可解决、可继续的独立工作；不得只写“环境问题” |
| `done` | 任务规定的产物、验证与资格实际满足 | commit/patch 身份、真实命令、完整结果/日志、证据索引、ledger 变更和已知范围 |

文档任务按文档标准完成，不能据此完成实现任务。完整验收受阻时保留局部成果，不能缩小定义逃过 gate。反例推翻结论须追加证据、重新打开任务/资格；失败 trial 不删除。

## 7. STATE、ADR、ledger 与六段经验

### 7.1 STATE 的最低内容

暂停或交接前更新：checkout/commit/dirty 范围、任务与文件负责人、运行命令/PID/证据目录、已测与未测 gate、阻塞及恢复条件、下一动作、ADR/contract/ledger 版本。摘要链接日志，区分已提交代码、未提交实现和未入索引证据。状态与磁盘不符时先核查修正。

### 7.2 ADR 与资格账本

ADR-001～011 不重编号；新决策取未用 ID。依模板记问题、候选、证据、选择、代价、迁移/回滚、验证范围和 supersedes；影响语言、SQL、wire、缓存或性能政策时同步契约与消费者。

`compatibility/ledger.json` 每项资格绑定格式/profile/平台/版本和证据路径；planned 不等于 supported。已知不兼容、未测试和受限支持保留具体边界，不能把同名表或工具数量当兼容证明。支持级别升级由集成者在必需 gate 通过后写入；被推翻的资格保留历史并撤回当前声明。

### 7.3 六段经验记录

使用模板创建 `docs/experience/<date>-<task>-<topic>.md`，严格保留六段：

1. **现象**：用户可见问题、触发条件和影响范围。
2. **证据**：输入/source/build 身份、复现命令、原始数据与最小差异。
3. **根因**：已证实的因果；尚未证实就明确写假设。
4. **最终方案**：真实采用的改动、为何有效、commit/ADR；未定稿不伪称最终。
5. **失败方案**：尝试过的方案、失败证据与未选理由，防止后续重走。
6. **验证范围**：执行过的测试/平台/样本、未验证处、回滚与残余风险。

普通进度不必写经验；不重写原始数据迁就根因。

## 8. Benchmark 与证据目录

性能定义和阈值只以 [验证规范](04_VALIDATION_AND_PERFORMANCE.md) 为准。以下是运行证据组织，不是新增基准任务；本文不执行测试。

| 路径 | 内容 |
| --- | --- |
| `benchmarks/workloads/<id>.json` | 版本化 fixture/profile、A0/A1/A2/B0/B1 组别、窗口、缓存/线程/预算、重复与统计方案 |
| `benchmarks/README.md` | 已实现的准备/运行/比较命令，输入获取与校验，机器要求、时间预算 |
| `artifacts/benchmarks/<run_id>/manifest.json` | workload 摘要、源码/二进制/输入/工具链、runner、顺序、实际参数与起止时间 |
| 同目录 `trials.jsonl` | 每次 warmup/正式 trial 的原始 wall/CPU/资源/状态；失败轮和排除理由仍保留 |
| 同目录 `certificates/` | 每 trial 完整结果证书及等价比较，不只行数或首屏 |
| 同目录 `logs/`、`summary.json` | 有界原始 stdout/stderr 或内容摘要/存储引用；可重算统计及结论限制 |
| `artifacts/index.json` | 新证据相对路径、SHA、类型、任务、产生程序/commit、结果和替代关系 |

`run_id` 唯一，时间含时区；原始 trials 不覆盖，新统计另存并关联。日志去凭据，私有 APK 不公开；省略大帧仍保留 hash、长度、生成方法与来源。B0/B1 未实现就记未运行，不用公式填 trials；完整消费/证书/缓存条件成立才比较。更换最佳 A 时保留 A0，不删除旧记录变分母。

## 9. CI 分层与不可虚假 skip

| 层 | 执行目标 | 失败/未运行处理 |
| --- | --- | --- |
| 每次变更 | format/lint、相关单元/属性、契约和小语料 | 保存命令与测试数；失败阻止对应合入 |
| 合并/集成 | 真实 differential、SQL/profile、生命周期、Tier 1 集成 | 依变更范围执行必需 gate；缺 runner 不算通过 |
| Nightly | 广语料、持久/故障、并发、固定预算 fuzz | 保存 seed、工具链、覆盖与所有异常；修复进入回归 |
| 性能专线 | 固定资源、同机配对、完整消费 | 独占资源并保留所有 trial，不把 PR 共享 runner 波动当结论 |
| Release candidate | advertised 能力、原生平台、完整 HostLab、恢复/回滚、发布资格 | 缺必需样本或平台阻塞对应资格，不能发布后再补证明 |

CI 报告必须区分实际成功、失败与未执行的原因。允许不适用测试，但要说明与变更/发布范围的关系；缺依赖、私有 fixture、预算或命令不是“不适用”。不得用 `continue-on-error`、全局 catch、空 golden、跳过 comparator 或选择性删除失败轮，把必需 gate 洗成绿色。

测试按风险和门槛选择：文案不跑全套基准；输入/schema/事实/缓存改动跑对应语义和失效测试。充分验证后推进下一任务，不无目的重复。

## 10. 中断与断点恢复

恢复读取顺序固定为：

1. 最新用户指令与实际仓库约束；确认是否改变范围或授权。
2. `STATE.md` 和实际 git/worktree/进程状态；不要先重跑耗时任务。
3. `tasks/backlog.json` 当前任务及依赖，只找下一项可执行工作。
4. 相关 ADR、`contracts/` 与核心契约；确认没有用旧字段/生命周期继续实现。
5. `compatibility/ledger.json`、`artifacts/index.json` 和当前任务原始日志/证书。
6. 对应经验记录、迁移/验证文档；历史问题才回查 `evidence/index.json`。

先核实后台进程是否仍在运行、输出是否完整、文件 lease 是否仍有效，再决定继续等待、收集结果或重新运行。只对本任务可确认归属的进程/暂存文件操作；不要无差别 kill 或清缓存。部分 artifact 没有最终完成 manifest 时不作为完整成功。

恢复后报告确认项、缺口、下一动作/负责人。聊天只助定位，不替代证据；新 steering 不自动抹去已完成任务。

## 11. 发布包与回滚操作

### 11.1 发布前形成具体可审查结果

按固定源码/锁文件构建，记录各平台产物 SHA、toolchain/features、依赖/许可与 ABI/schema。包内包含真实命令、ledger、限制、证据入口、配置/缓存规则及回滚说明；凭据/私有 APK 不打包，符号与大捕获帧按分发策略处理。

在干净目录实际安装并运行声明的接口和 fixture，验证版本/能力与包 manifest 相符；不能只从开发目录启动。Windows/Linux 原生验收分别记录；其他平台未测不 advertise。性能替代资格不足时可发明确的预览/研究包，不使用性能替代成功措辞。

功能预览由 MDD-055/MDD-073 输出；MDD-083 的正式性能发行仍以 MDD-082 为前置，不伪造任务完成来解锁。MDD-062 的门禁事实复用按本次发行范围验收：启用或宣称时必须通过；未采用则保留独立原门禁并完整计入 E。

发布、默认切换、远端派发按会话已有授权执行；未授权时先完成构建、证据、变更和回滚材料，再把具体发布动作交用户审阅，不让此前开发停在提前询问。

### 11.2 回滚步骤与检查点

1. 记录当前与候选版本、backend/profile、配置、缓存命名空间和 in-flight 任务，保留可验证的上一版产物。
2. 停止向候选 backend 接纳新任务；按契约 drain 或 cancel 已有任务，不丢弃仍被 lease 引用的文件。
3. 显式切回旧 backend/配置，核对实际二进制与能力；不能让 `--backend dexsql` 名称偷偷指向候选。
4. 不复用不兼容 schema 的索引/checkpoint；隔离候选产物供诊断，不清空用户全部缓存或覆盖历史完整报告。
5. 执行固定小 fixture、接口和必要完整报告核验，确认回滚后的真实来源、结果与终态；记录恢复耗时和残留任务。
6. 更新 STATE、ledger、ADR/事故经验与 artifact index，保留失败证据。需要回滚的是候选行为，不能把输入变化/完整性错误“回退洗白”。

## 12. 每次交接的最小内容

交接列明：任务/状态、commit/dirty diff、改动原因、实际命令/结果、证据与资格变化、未测/阻塞、运行进程/lease、下一动作/写入范围/回滚点。核对 STATE、backlog、ledger、index 一致，明确 CPU 是否释放。规划或局部验证按真实范围交付；本文仅是规范，没有运行新性能测试或实现引擎。
