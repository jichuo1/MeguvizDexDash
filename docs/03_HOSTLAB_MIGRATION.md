# 03 — HostLab 迁移契约与工程任务拆解

项目：**MeguvizDexDash**。本文是可交给工程 AI 执行的迁移规格，不是实现完成报告。文中任务状态只有 `todo` 与 `existing evidence`；`complete`、`partial` 等其它词仅描述运行协议字段。

固定参考仓库：`jichuo1/innocent-lab-host-analysis`，提交 `8782f43d537c442905123e35af325c412caa5188`。研究工作区只读副本为 `/workspace/scratch/acc0e5058f47/research/desktop_v2/hostlab`。2026-10-26 的源码、真实历史 artifact、公开 APK 实验是本计划输入。执行者先核对 SHA，不得将随后发生的 main 变化混进基线。[S01]

## 1. 工程目标、边界与完成定义

MeguvizDexDash 要承担桌面/云端 DEX 分析软件的完整职能：输入容器与 DEX、事实与关系、查询、Smali、Manifest/资源、会话、机器接口、缓存及错误与资源管理。HostLab 是首个真实客户与适配器；通用核心不能编入 BIL 包名、FEATURE、候选名单、协议家族、版本适配决策或 HostLab 的云调度规则。

**DexKit 和 Android 手机端迁移不在本项目范围。DexMeguviz 是独立项目，M0 不依赖其存在或实现。** 将来如复用 parser、IR 等能力，必须通过独立版本包或窄 ABI 明确内存所有权、生命周期、错误语义、版本与性能；不得复制共享可变全局状态，也不得让本计划等待另一个项目完成。

必须区分三种交付程度：

| 程度 | 允许的声明 | 不能据此声明 |
|---|---|---|
| `hostlab-audit-v1` profile | 固定必需 SQL、27 个 FEATURE、surface 与门禁证据可由新引擎路径完整完成 | 全部 DexSQL SQL/工具已兼容 |
| `dexsql-0.1.0-compat-v1` / `dexsql-0.1.1-compat-v1` profile | 逐项经过冻结 schema/行为/corpus 验证的兼容功能 | 未跑过的工具、格式、函数也等价 |
| 完整职能替换发布 | 本文完整工具矩阵与产品必需能力通过；生产任务无需 DexSQL；可独立安装运行 | 只是启动成功、短查询快、包装了现有 DexSQL |

必要审计查询仍由 DexSQL 执行、整个 audit 遇到缺能力便回退到旧后端、忽略资源工具或 Smali，均不满足完整替换完成条件。迁移期可以保留显式应急后端；验收报告必须写出每项实际执行后端、fallback 次数及原因。必需 audit corpus 的 B0/B1 成功验收要求 fallback 次数为 **0**。

初始实现沿用核心规格中的约定：Rust 包 `mdd-*`、C ABI `mdd_*` major 1、worker 协议 `mdd-wire/1`、能力文档 `mdd.capabilities.v1`。这些均为 `todo` 设计，不代表当前目录已有实现。HostLab 新实现标识采用 `meguvizdexdash`；不得伪造 DexSQL 的版本、签名或固定二进制摘要。

## 2. 已有证据登记：不能重复算作新工作成果

| ID / 状态 | 已核查的现象与证据 | 归因边界 / 对方案的要求 |
|---|---|---|
| E01 / `existing evidence` | 安装器固定 DexSQL 0.1.0；Linux SHA256 `f9e795e1e33547fdda451f592fe54c85e99c2138575f599540f5a860c1cef00c`；环境覆盖路径也校验相同摘要。[S02] | 现状不是默认使用 0.1.1。新增安装器/provider manifest，不放宽旧固定校验冒充新后端。 |
| E02 / `existing evidence` | batch 已按后端共享一个 stdio session/dataset；native audit 已使用一个交互 CLI、64 KiB reader、8 块队列和 code_items 范围过滤。[S03][S04][S05] | 会话复用、分块读取和候选范围优化已存在，不计为新引擎独占收益。 |
| E03 / `existing evidence` | source SHA、物理 DEX inventory、稳定分页、sealed checkpoint、分组 runner、artifact 摘要及源码快照均已有实现。[S03][S06][S07][S08][S09] | 迁移应保留并加强相同身份链；不能为性能删除验证。 |
| E04 / `existing evidence` | 真实 run 40067936875 中，两个 worker 为 94.630143 / 85.572220 秒，structural 13.663421 / 11.911596 秒，surface 56.525247 / 50.801524 秒；22 个工具摘要匹配固定 main。[E1] | 这是固定 0.1.0、预取样本、保留 OS cache、每样本一轮配对的既有记录，非新引擎成绩。 |
| E05 / `existing evidence` | NewPipe 55,763 行完整方法导出，真实原 HostLab CLI 管道中，0.1.0 → 0.1.1 的逐轮倍速中位 2.8847×；仅该工作负载，全部行 hash 相同。[E2] | 上游升级已有价值。不能把此收益归给自研，也不能直接外推整个 BIL audit。 |
| E06 / `existing evidence` | 独立 consumer 回放与 batch 格式原型只证明组件优化；没有完整 MeguvizDexDash 引擎对 BIL 的实测。[E3] | 生产者、消费者通过 pipe 重叠，组件时间不可串行相加。根因结论需真实联合计时。 |

必须使用“现象 → 原始证据 → 可证根因/未证假设 → 方案 → 失败条件 → 验证范围”的记录方式。比如：surface 占比约 59% 是测量；其包含 SQL、格式输出、Python 聚合与指纹是源码事实；其中恰有多少秒属于 parser 仍未知，不能随意补一个百分比。

## 3. 三层接口必须分别迁移

### 3.1 原生 DexSQL MCP：12 个工具

下列名称、参数来自 0.1.0 `tools/list` 原始录制及 0.1.1 发现记录，不是根据旧印象命名。HostLab 当前 batch 直接使用其中 `open_dataset`、`query`、`decode`、`get_manifest`、`close_dataset`；其余工具仍属于独立软件完整能力面，不能因为 HostLab 暂未调用就从最终替换范围删去。[S03][E4]

公共要求：stdio 的 stdout 仅 JSON 协议消息，诊断走 stderr；二进制列批走专用 worker IPC/SDK，不能混入 MCP stdout。数据集/文件 ID 以返回值为准；`input_index` 是有序输入集合中的归档身份。SQL/列表按行续页，Smali/XML/文本的 offset 为相应文本的 UTF-8 字节，hex 资源 offset 按原始字节；方法列表另有 method_offset。每次返回必须能判断输入覆盖、事实覆盖、执行是否完成以及输出是否截断。

| 工具 / 迁移状态 | 原入口关键参数 | 必须保留的功能与验收 | HostLab 当前使用 |
|---|---|---|---|
| `open_dataset` / `todo` | `inputs[]`, `timeout_ms` | 单/多 APK、DEX、ZIP、JAR；确定输入顺序、物理成员与逻辑 DEX 映射、诊断与 `has_dex`；打开后续查询共享数据。资源专用归档可以没有 DEX；audit 的必需 DEX 校验不能错误上移成所有工具的全局限制。 | 是 |
| `list_datasets` / `todo` | 无 | 返回当前服务实际存活的数据集；关闭、取消、配额拒绝后的状态可观察；不泄露其他进程/租户上下文。 | 间接生命周期验证 |
| `close_dataset` / `todo` | `dataset_id` | 明确关闭/并发请求行为、回收句柄与预算；重复 close 和 unknown ID 按声明的兼容 profile 验证。 | 是 |
| `list_tables` / `todo` | 无 | 不要求打开 APK；列出真正支持的事实表/视图，不能把未实现表当空表。 | 不直接调用 |
| `describe_table` / `todo` | `name` | 列名称、类型、NULL、单位、ID 作用域与表说明；未知表明确错误；结果与 SQL view 实际 schema 一致。 | 不直接调用 |
| `query` / `todo` | `dataset_id`, `sql[]`, `named_temp_queries[]`, `limit`, `offset`, `max_bytes`, `timeout_ms`, `timing` | 多语句顺序与 statement result；类型化单元格、完整值、SQL 元数据、total/next/truncated、诊断；TEMP 的作用域与依赖必须声明。HostLab v1 仍只允许其既有 SELECT/WITH 请求边界。 | 是 |
| `decode` / `todo` | `dataset_id`, `method` / `method_idx` / `class`, `file_id`, `mode`, `method_offset`, `method_limit`, `offset`, `max_lines`, `max_bytes`, `timeout_ms` | 唯一方法身份；mode 为 summary/smali/context，完整保留寄存器/label/payload/异常处理。Smali offset 是 UTF-8 字节，不是指令或行号；context 是单独索引，不能拿其 offset 续接全文。方法列表页与单方法页分开；同名多 DEX 不挑第一项冒充唯一。 | 是 |
| `get_manifest` / `todo` | `dataset_id`, `input_index`, `mode`, `limit`, `offset`, `max_bytes`, `timeout_ms` | 二进制 XML 解析，mode 为 summary/xml；summary 的 permissions 按列表续页，xml 按 UTF-8 字节；来源、权限/组件等值及截断完整保留；不能用文件名/包名猜测代替解析。 | 是 |
| `get_manifest_components` / `todo` | `dataset_id`, `input_index`, `kind`, `only_exported`, `limit`, `offset`, `max_bytes`, `timeout_ms` | 组件类型、exported 规则、过滤和续页；使用独立 Manifest fixtures，而不是只测返回空列表。 | 否 |
| `list_resource_files` / `todo` | `dataset_id`, `input_index`, `prefix`, `limit`, `offset`, `max_bytes`, `timeout_ms` | 归档成员清单、路径/前缀/大小、分页；ZIP 成员校验、重复名和资源-only APK。 | 否 |
| `read_resource` / `todo` | `dataset_id`, `name`, `input_index`, `format`, `offset`, `max_bytes`, `timeout_ms` | format 的真实枚举为 auto/hex：auto 将 Android XML 解成 XML、UTF-8 保持文本、其它 bytes 用小写 hex；hex 强制原字节。文本/XML 按 UTF-8 字节、hex 按原字节续页；保留完整值，不将截断当完整内容。 | 否 |
| `query_resources` / `todo` | `dataset_id`, `input_index`, `resource_id`, `resource_type`, `name`, `configuration`, `contains`, `limit`, `offset`, `max_bytes`, `timeout_ms` | `resources.arsc`、配置限定符、资源 ID/名/值及过滤；多输入和同名不同配置不能串联错。 | 否 |

0.1.1 的 `compact` 是 `query`、`decode` 及五个 APK 工具的新增可选表示，生命周期与 schema 工具不因此改表示。当前 `Session.call()` 从 text content 拼接 JSON，直接要求 `compact=true` 会遇到空 content；先实现统一 envelope normalizer，优先读取并校验 `structuredContent`，再显式启用 compact，不能只切 flag。[S03][E4]

兼容 schema 的数值边界也需冻结：0.1.0 query 页 `limit` 1..1000，decode `max_lines` 1..1000、`method_limit` 1..50，Manifest/资源列表 `limit` 1..200。省略值、null、0 和越界不是同一个语义；从原 schema/黑箱用例逐项导出 golden，不根据本表自行补默认值。

### 3.2 HostLab legacy dexq：实际是 8 个工具

这是 Python/SQLite/Androguard 旧实现的接口，不能与上面 12 个原生工具混为一套。它在固定代码中仍服务旧 CLI、`refs.detail=sites` 等路径；当前计划不删除它，不把 SQLite SQL 自动改成另一方言。[S10]

| 真实工具 | 现有契约 | 新适配器要求 / 状态 |
|---|---|---|
| `open_dataset(inputs, rebuild=false)` | 建/复用磁盘 SQLite 索引，返回 totals 与 `dex_files` | `todo`：保留旧 provider；不把 rebuild 错映射为删除其他引擎缓存 |
| `list_datasets()` | 当前 server 内 dataset → inputs | `todo`：provider 命名空间分离 |
| `close_dataset(dataset_id)` | 忘记 session ID，保留磁盘索引 | `todo`：不误删共享 snapshot/cache |
| `describe_tables()` | 一次返回旧索引 schema 与示例 | `todo`：不可偷换成原生 `describe_table(name)` |
| `query(dataset_id, sql, limit=100, max_cell_chars=300)` | 单个只读 SELECT/WITH，TSV、页限/单元格预览/总输出 footer；SQL 内部值完整 | `todo`：显式 TSV compatibility；截断 footer 是未观察到尾部，不能转成完整负结果 |
| `decode(dataset_id, method, max_chars=12000)` | 旧文本 Smali 输出；legacy 没有调用参数 `file_id` | `todo`：保留差异，禁止假装已支持文件坐标 |
| `find_refs(dataset_id, kind, target, limit=100)` | `method/field/string/type`，输出 `file_id,class,method,proto,offset,op` | `todo`：site 明细与方法级关系分别建契约；不以方法列表替代 offset/op |
| `apk_info(path)` | 返回该 APK 的真实信息 | `todo`：明确与 get_manifest 的 schema 映射，不能假定字节级相同 |

旧 SQL 表包括 `dex_files/classes/methods/fields/method_ids/field_ids/strings/meta`。例如旧 `methods.class/name/proto` 与原生 `class_methods.class_descriptor/method_name/method_descriptor` 不是相同列名或方法全集；跨 dialect 不做隐式拼接/字符串替换。[S10]

### 3.3 HostLab remote MCP：另有 12 个编排工具

这些是本地 stdio 的云任务编排工具，当前没有据此证明存在公开 HTTP 分析网关。新增 HTTP 服务是独立部署/鉴权决策，不是现有迁移入口的事实。[S11]

| 工具 | 保留行为 | 迁移新增点 / 状态 |
|---|---|---|
| `plan_version_matrix` | 1..40 精确样本、最多 4 runner 的无派发计划；固定/自适应分组 | `todo`：把 engine/profile/capability digest 纳入冻结计划 |
| `submit_version_matrix` | durable queue；稳定键固定原拓扑；不自动重放 unknown dispatch | `todo`：B 工作负载与 shadow 身份隔离，不重复派发 |
| `advance_version_matrix` | 仅在调用者要求推进时填充可用槽位；deadline 停止新派发而非取消已接受任务 | `todo`：沿用队列与预算，不内核化 GitHub 调度 |
| `version_matrix_status` | 只刷新状态，不派发新任务 | `todo`：不能因 engine missing 在 status 内安装/执行 |
| `version_matrix_result` | 校验 artifact 后分页收集；prefetch-only 不执行比较/派发 | `todo`：比较报告绑定 engine/profile 与结果 schema |
| `recover_version_matrix` | 明确恢复失败/跳过项，排除运行中与未知派发；特定 opt-in 才能重复未验证结果 | `todo`：不能因升级内核复用不兼容 checkpoint |
| `plan_analysis` | 最多 16 个任务；只规划，不执行、不当作分析证据 | `todo`：分离 SQL dialect 与 implementation，公开选择理由 |
| `submit_analysis` | 一次 APK fetch、每 backend 一次 session；bounded SQL 续页；显式 verified resume | `todo`：mdd snapshot 身份进入任务与恢复绑定 |
| `submit_job` | 保留 audit/decompile/query/decode/string_refs/info 等旧操作与源绑定 | `todo`：旧请求仍走旧语义；新 backend 需协商入口 |
| `job_status` | 返回队列/运行/完成状态，不等待 | `todo`：failure/partial 不能标成 successful complete |
| `list_jobs` | 列出已有任务 | `todo`：不混入 shadow 的可发布结果 |
| `job_result` | 根据 request/run/attempt 验真、读取限定文件并分页 | `todo`：跨引擎结果无法被旧 sealed receipt 冒认 |

## 4. CLI、Session、audit 与 runner 的实际路径

### 4.1 现有命令和生命周期

| 边界 | 当前实现 / `existing evidence` | 迁移要新增 / `todo` |
|---|---|---|
| `hostlab dexq` CLI | `mcp`, `capabilities`, `plan`, `batch`, `index`, `query`, `decode`, `refs`, `info`, `tables`；普通旧命令默认 SQLite，显式 `--backend dexsql` 转 batch。[S12] | 保持已有命令输出与 exit code；新增明确 `meguvizdexdash` provider 与 capabilities；不把命令 `index` 宣称为已构建全部延迟事实。 |
| structured batch | `dexsql --threads N mcp --timeout-ms T --max-datasets 1`；每 backend 顺序执行一个 session。[S03] | `mdd` worker 的版本化 adapter；一次 batch 的 snapshot 固定、任务共享 facts 与总预算；SDK 入口可独立复用。 |
| `Session.open/sql/execute` | open → dex_files → query/locate/refs/decode/info → close；MCP typed DTO 由 text JSON 读入。[S03] | 统一 envelope/typed cells、错误分类、coverage、cursor 和 source mapping；先保持旧 DTO，再提供新 native result。 |
| complete native audit | `dexsql --threads 2 query --input APK --interactive`，每 APK 一进程；前后 SHA，规则、class count、surface、关闭。[S04][S13] | B0 使用显式 compatibility profile；B1 用 `mdd-wire/1` 的 typed batch，替换传输边界而不是删任务。 |
| `native_graph` | 分批 metadata/member/signature 查询，完整 file/pool 坐标；Python 继承与候选规则。[S14] | 查询接口与通用 facts 可换；BIL 相关 owner 列表、推断与规则继续在 adapter。 |
| `native_surface` | 每 DEX 的类、成员、code_items、method_calls、协议与原始代码指纹；最终共用 summarize。[S05] | 合并同源事实/字节读取、批传输和通用 fingerprint 算子；分类、规则 hash、最终报告语义留 HostLab。 |
| intake/home gates | 原生结果后仍执行独立 Python gate；重复读取 DEX。[S15] | 第一阶段先保留；之后用同 snapshot facts 移植，不计未量出的 22 秒为必然节省。 |
| remote runner | `remote_job.py` → batch / runner_worker / analyze / priority_analysis；固定 checkout 与 exact sample。[S16][S17] | 安装及 capability manifest 分离、backend pin 加入 request/receipt；不让 engine 下载 APK 或持有云凭据。 |

当前 batch 请求约束：最多 16 项、30,000 UTF-8 bytes，线程默认 2、范围 1..6，再按 CPU 数限制；timeout 默认 180 秒、范围 1..600；batch 结果总预算 2 MiB。query SQL 最多 12,000 字符、页大小 1..1000、offset 0..99000；自动分页默认最多 8 页/1000 行/1 MiB，可选上限 32 页/10,000 行/1 MiB。这些是当前用户协议，不因为换 Rust 内核静默放大。[S03][S06][S18]

当前 audit 的边界不同：全事务默认 900 秒，SQL 256 KiB、单行 4 MiB、传输 512 MiB；默认 complete rows 500,000、解码值 128 MiB；method_calls 场景单独允许 1,000,000 行/256 MiB。迁移应保留分别配置，不能将交互 query 的小页限强行套在完整 audit 上，也不能让完整 audit 接受被页限截断的结果。[S04][S05]

### 4.2 将 implementation 与 dialect 分开

旧 schema 1 的 `backend=sqlite|dexsql|auto` 与 SQL `dialect=sqlite|dexsql` 有固定关系，已有 raw SQL 不重写。新增实现不能简单把字符串 `dexsql` 解释为“任意能运行 SQL 的 engine”。[S18]

`todo` 设计：在新版本 request 或显式能力协商中区分 `implementation=meguvizdexdash`、`dialect`、`compatibility_profile`、engine build SHA 与 adapter schema；旧 schema 1 的强制后端语义继续有效。`auto` 策略变更要版本化并记录 selection reason。未验证的 profile 不能注册为可用。安装器同时保留 A0/A1/B 的独立路径与摘要；不修改 A0 固定摘要来规避验证。

## 5. 必须覆盖的 HostLab 查询与数据契约

### 5.1 17 张实际消费表的最低列集

这是从 `native_graph/native_rules/native_surface/native_audit/analysis_plan/analysis_batch` 抽出的 **最低必需集合**，不是完整 DexSQL schema。`cf.*`、`cm.*` 的兼容输出还要求冻结原完整 schema；不能只实现本表列却宣称 wildcard 已兼容。通用产品 profile 的额外表、算子、SQL 功能须在 ADR-002 的 corpus 中另列并逐项验收。[S03][S05][S13][S14][S18][S19]

| 表 | 当前最低读取/过滤/排序列 | 语义或单位必须固定 |
|---|---|---|
| `dex_files` | `file_id,entry_name,string_pool_id` | file_id 为 snapshot 内映射；string_pool_id 是字符串坐标，不可随意用 file_id 代替 |
| `strings` | `string_pool_id,string_idx,value` | 跨 DEX 用池身份；完整 MUTF-8 解释、NULL/空串区别，不能按 value 去重改 ID |
| `types` | `file_id,type_idx,descriptor` | 局部 type_idx，Signature 注解定位 |
| `classes` | `file_id,class_idx,class_def_idx,descriptor,access_flags,superclass_descriptor` | definition 身份与声明顺序；同 descriptor 多 DEX 不能覆盖 |
| `class_interfaces` | `file_id,class_idx,ordinal,interface_descriptor` | JOIN 同 file_id/class_idx；ordinal 与类声明关联 |
| `class_fields` | `file_id,class_idx,kind,field_idx,class_descriptor,field_name,field_descriptor,access_flags` | 已定义字段、static/instance kind、声明顺序、generic signature 覆盖规则 |
| `class_methods` | `file_id,class_idx,kind,method_idx,class_descriptor,method_name,method_descriptor,access_flags` | 已定义方法、direct/virtual kind；不能混入只被引用的外部方法 |
| `methods` | `file_id,method_idx,class_descriptor,return_descriptor` | method ID 与 class_methods 的定义关系通过双键关联 |
| `annotation_directory_entries` | `file_id,class_idx,entry_kind,entry_idx,annotation_set_off` | field/method 注解目标及可能的 NULL set offset |
| `annotation_set_entries` | `file_id,annotation_set_off,annotation_off,ordinal` | set→annotation 关系和顺序 |
| `annotations` | `file_id,annotation_off,type_idx` | 先按当前 DEX 的 Signature type_idx 过滤 |
| `annotation_elements` | `file_id,annotation_off,ordinal,value_index,depth,value_kind` | Signature 的 depth=1、string 元素按 ordinal 拼接；value_index 需经过池映射 |
| `method_strings` | `file_id,method_idx,method,method_class,value` | 字符串引用关系按固定 schema 的重数语义；特定 DISTINCT 只由具体查询要求 |
| `code_items` | `file_id,method_idx,insns_off,insns_size` | offset 是字节坐标；insns_size 在当前 adapter 中乘 2 转字节；边界/对齐校验不可省 |
| `method_calls` | `file_id,method_idx,method,callee,callee_class` | 多调用点的重数使 `COUNT(*)` 有意义；不能只保留无重数边 |
| `method_field_accesses` | `file_id,method_idx,method,field` | 字段引用身份保持 owner/name/type，不按短名 JOIN |
| `method_used_types` | `file_id,method_idx,method,type_descriptor` | 类型引用对应方法及所属 DEX |

### 5.2 冻结 query-template corpus

每个模板的输入、完全展开 SQL、参数、source snapshot、schema、ordered rows 或合法 multiset、row count、SHA256、coverage、错误、执行后端都应保存为独立 golden。不要只保存“查询无异常”或前 20 行。

| 模板 ID / 状态 | 必须覆盖的真实模式 | 主要来源 |
|---|---|---|
| Q01 / `todo` | `SELECT file_id,entry_name FROM dex_files ORDER BY file_id`，另取 string_pool_id | Session/open、Graph 初始化 |
| Q02 / `todo` | 按 descriptor IN 批量类元数据；按 kind/index 有序的 `cf.*`/`cm.*` | native_graph.load/load_meta |
| Q03 / `todo` | class_interfaces 与 classes `JOIN ... ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx` | native_graph.load_meta |
| Q04 / `todo` | annotation_directory → set_entries → annotations → elements → strings 的分批有序关系；`IN`、`OR`、depth/string 过滤 | native_graph.signatures |
| Q05 / `todo` | class_methods JOIN methods，双键匹配、return_descriptor、`SELECT DISTINCT` | native_graph.discover |
| Q06 / `todo` | `method_strings` 中按 method_class 的候选集、两个 `LIKE` 分支及 `ESCAPE '\\'`、DISTINCT | native_rules.run |
| Q07 / `todo` | `SELECT COUNT(*) AS n FROM classes ORDER BY n` | native_audit |
| Q08 / `todo` | 按 file_id 逐 DEX 的 classes/class_fields/class_methods；family prefix OR、lower、LIKE、精确 Python 分类 | native_surface.per_file |
| Q09 / `todo` | code_items 的 `method_idx BETWEEN lower AND upper` + Python 精确 membership，返回原始 code 字节区间 | native_surface.code_locations |
| Q10 / `todo` | method_calls 按 `file_id,method,callee` GROUP BY、COUNT(*)、ORDER BY；callee 家族/协议联合过滤 | native_surface.scan |
| Q11 / `todo` | class_methods 中 protocol 定义；固定集合 IN 与 `Lcom/bapis/%Moss;` 匹配 | native_surface.scan |
| Q12 / `todo` | `locate` 的 class/method/field 三类模板；`refs` 四种关系；`LIMIT limit+1` 的溢出探测 | analysis_plan.locate_sql/refs_sql |
| Q13 / `todo` | 原 CLI shape：`SELECT * FROM (<SQL>) AS hostlab_shape LIMIT 0`；实际值：CASE/NULL/hex(CAST AS TEXT) 包装；marker SELECT | native_cli.rows/table |
| Q14 / `todo` | arbitrary SELECT/WITH 的稳定外层 ORDER BY、SQL 自己的 LIMIT/OFFSET 与响应页限的独立语义；重复行、空结果、长值 | analysis_plan + analysis_paging |
| Q15 / `todo` | 旧 SQLite 表、`||` 拼 descriptor、length/substr 长值读取及 TSV 预览 | legacy compatibility；不得混到原生 schema |
| Q16 / `todo` | 声明支持的 native TEMP/named_temp_queries、多语句、聚合/子查询等完整产品能力 | 原生工具 schema 与版本化 SQL corpus；不是 HostLab v1 自动扩权 |

最低算子/语义集合：投影/alias/wildcard、整数与文本/NULL、`=`, `IN`, `BETWEEN`, `AND/OR`、括号与转义字符串、`IS NULL`、CASE、CAST AS TEXT、hex、lower、LIKE + ESCAPE、INNER JOIN、多键 GROUP BY、COUNT(*)、DISTINCT、ORDER BY 多键、LIMIT/OFFSET、子查询及 Q13 wrapper。旧 dialect 还需要已用到的 `||`, length, substr。SELECT/WITH 被接受不表示所有复杂 SQL 已获兼容；CTE、递归、窗口、UNION、更多函数与相关子查询按 ADR-002 独立测试和 capability 表公开。

**SQL 实现主路线：typed IR 与算子快速路径，加首轮默认验证固定版本 SQLite 的只读 virtual-table 兼容桥。** 数据仍由 snapshot facts provider 提供，不先把全部 DEX 事实 ETL 成一份 SQLite 全量库。ADR-002 必须用冻结语料验证 SQLite 与目标 profile 在类型、NULL、排序、LIKE、聚合、LIMIT、函数、TEMP 等处的实际差异；不预设“都叫 SQL 就天然等价”。桥层解析/执行错误不能通过删除 WHERE、改写 dialect 或返回空表规避。

### 5.3 两个容易造成虚假等价的细节

当前 `native_surface.prefix` 明确把原生大小写不敏感 LIKE 当作**候选超集**，随后 Python classifier 做精确大小写判断。新引擎若改变 LIKE 或提前移除精确 gate，会改变报告；SQL 的标准化优化必须保留这个两层关系。[S05]

`native_graph.signatures` 已正确经 `dex_files.string_pool_id` 连接 strings，不能把“修复跨 DEX 字符串 JOIN”当作 HostLab 尚未修复的问题。新通用引擎仍须保持来源局部坐标，特别是 041 共享数据/逻辑 DEX；file_id 和 pool_id 在只有一个 DEX 的样本里碰巧相同，不构成正确性证明。[S14]

## 6. BIL 规则、surface 和结果格式保留条款

27 个 FEATURE 来自固定 `analysis/run_intake.py:EXPECTED_FEATURES`，必须保留名称、状态与 detail 语义；不把手机端的另一组 33 规则混入本工作负载。[S20]

```text
block_update, player_default_quality, comment_free_copy,
description_free_copy, home_top_bar, mine_entry, mine_vip,
dynamic_tabs, full_number, player_portrait, player_status_bar,
home_recommend, video_relate, home_tabs, mine_components,
story_purify, splash_ads, bottom_bar, teenagers_mode,
comment_filter, comment_purify, comment_topology, comment_section,
paused_ad, home_banner, merchandise, game_promotion
```

保留 `FOUND/MISSING/PARTIAL/AMBIGUOUS` 区别以及 discoveries、class count、`META audit_complete true` 的生成条件。格式错误、输入未加载完整、查询超时、source 改变或必要 facts 未建立都不是功能 `MISSING`。静态 `FOUND` 也不等于设备上运行成功；报告继续保留 `scope=offline_static_only`、`runtime_verified=false` 与未覆盖 installer 的说明。[S13][S15][S20]

必须保留的 surface 证据包括 class_records、invoke_edges、protocol_definitions、protocol_twins、unclassified_protocol_callers、discovery 等的重数；方法签名与字段顺序、原始代码字节 hash、resources.arsc/res XML 指纹、protocol/family 规则版本与 hash。代码指纹当前按 `legacy_body_order` 和原指令字节计算，不能改用“语义等价 opcode 集合”或忽略 debug/try 边界而仍报告原同一个指纹 schema。[S05][S21]

现有 `verify_audits` 对 20 个字段比较完整摘要，其中仅 `class_records/invoke_edges/protocol_definitions/protocol_twins/unclassified_protocol_callers/discoveries` 按 multiset 排序，且**保留重复元素**；其它字段按原语义。跨版本 changes/resource_changes/verdict 也必须一致。增加新能力时新增 schema/profile 与测试，不把新增工作和“同样工作更快”混成一个对比。[S22][E1]

## 7. 生命周期、错误与完整性

### 7.1 统一结果模型与 adapter 映射

与核心文档统一的拟定模型如下，状态 `todo`：

```json
{
  "schema_version": "mdd.result.v1",
  "operation_status": "ok",
  "snapshot_id": "<immutable snapshot id>",
  "session_id": "<query session id; nullable for non-session operations>",
  "catalog_epoch": "0",
  "profile": "hostlab-audit-v1",
  "sql_dialect": "<separately negotiated dialect>",
  "coverage": {
    "scope_id": "<the requested immutable scope>",
    "input": "complete",
    "facts": "complete",
    "required_layers": ["<layers required by this operation>"],
    "issues": []
  },
  "execution": {"complete": true},
  "response": {
    "schema_id": "<versioned row schema>",
    "emitted_rows": 0,
    "total_rows": 0,
    "total_rows_exact": true,
    "more_available": false,
    "truncated": false,
    "next_cursor": null
  }
}
```

上面是结果契约摘录，完整 schema 以核心文档为准。`session_id` 类型为 string|null，TEMP 和 catalog_epoch 属于 session；profile 与 sql_dialect 分字段。`operation_status` 为 `ok/error/cancelled`；coverage 的 input/facts 都是 `complete/partial/unknown` 三态，不能把 unknown 压成 false 后再默认成功。facts.complete 以本 operation 声明的 required_layers 为范围：仅查询字符串不要求所有 CFG 已建立。execution 完成与输出页终止不同；完整输入上的一页正确结果也可能还有 more_available。完整 audit 验收还要求 `operation_status=ok`、`execution.complete=true`、所需 input/facts coverage complete、`truncated=false`、`more_available=false`、`next_cursor=null`。

HostLab 旧 `partial` 必须从 coverage、execution 与 response 的联合状态转换；禁止 `rows=[]` 自动意味着未命中。持久化负结果、生成 `MISSING` 或完整 audit 证据，必须证明所需输入/事实覆盖完整、执行完成且逻辑结果的未观察尾部不会影响该结论。首版采取严格策略：任何 partial/unknown/truncated 的负结果都不进入长期缓存。

### 7.2 仅明确不可用/不支持可显式 fallback

| 分类 / 新错误码 | 自动成功替代是否允许 | HostLab 行为 |
|---|---|---|
| Unavailable：`UNAVAILABLE_BACKEND` | 仅在显式策略允许的等价操作上 | 记录指定/选中 backend、原因和 capability；强制后端不伪装成功 |
| Unsupported：`UNSUPPORTED_CAPABILITY`, `UNSUPPORTED_QUERY` | 仅在显式允许、同输入/同结果契约且未产生业务副作用时 | 返回原不支持原因；完整 B 验收的必要 corpus 不允许借 fallback 通过 |
| `INVALID_INPUT`, `PARTIAL_INPUT`, `INCOMPLETE_FACTS` | 否 | 完整性失败，不映射 MISSING 或空结果 |
| `SOURCE_CHANGED` | 否 | 当前 snapshot/query/checkpoint 无效；不拼接不同代数据 |
| `QUOTA_EXCEEDED`, `DEADLINE_EXCEEDED`, `CANCELLED` | 否 | 保留未完成/取消与预算；不能静默换后端躲过预算 |
| 歧义/身份冲突、schema/cursor/checkpoint mismatch、`INTERNAL_FAULT` | 否 | fail，保留最小可复现证据；错误码由 versioned taxonomy 固定，不降格为 Unsupported |

现有代码的 `UnsupportedAudit` 还用于 duplicate class、041 fingerprint 或无法保持旧顺序等多种场景；迁移不能按 Python exception 类名一概放行 fallback。必须在 adapter 分清“明确未声明支持的能力”与“数据/身份不可信”。旧 `auto` fallback 行为是历史事实，新错误映射是要验证的显式契约；遇到冲突先记录，而不是把错误包装成一个可 fallback 的类型。[S13][S14][S05]

SQL 语法错误、名称/类型绑定错误也不能统称 `UNSUPPORTED_QUERY`；该分类必须对应已识别、明确未实现的合法能力。已经接纳输出页、改变 TEMP catalog 或其它 session 状态后，不跨后端重放同一个 operation。fallback 应在可证明安全的边界决定，不能混合前一个后端的前缀与后一个后端的尾部。

原生 mdd 的 cancel 只取消相应 query；兼容 profile 若声明 `compat_cancel_closes_dataset`，由兼容层执行对应生命周期。不得把原生取消语义硬套到 DexSQL profile，或在 dataset 已关闭后继续使用旧 ID。close 后新请求、已接受请求、未开始队列请求、进程崩溃与 quota 的组合都须有用例。

## 8. 分页、snapshot、checkpoint 和缓存

### 8.1 查询续页

现有分页已检查外层 ORDER BY、volatile 函数、schema/total/SQL 一致性、offset 单调推进、total 与 terminal count、row/byte/deadline；output_too_large 可在同一存活 dataset 内缩小页大小重试。它保留行重数，不通过 set 去重“修好”分页。[S06]

新 cursor 必须绑定 `snapshot_id + session_id + catalog_epoch`、有序来源身份集合、engine/profile/schema、query 与参数、稳定排序及分页位置。原生 cursor 与兼容 offset 区别必须显式：后者按原契约可能重新执行查询，不能伪装成一直持有原游标。SQL 文本和 count 一样仍可能在修改文件后混页，所以来源身份不可省。OFFSET 页限与 SQL 自己的 LIMIT 不是同一层，禁止替调用者改 LIMIT 来“续页”。没有唯一稳定顺序、含 volatile 值或 snapshot 失效时，自动续页拒绝或明确停止，而不是虚构稳定结果。

原查询完整值不能因 text preview 截断而丢掉；字节预算应在完整行/批边界停止，返回原因和 cursor。Smali 的 offset、方法列表的 method_offset、资源的 byte offset 分别校验，不复用一个无单位整数。

### 8.2 checkpoint

旧 checkpoint 已绑定 exact sample/request/tool/native backend、source_unchanged、sealed 摘要与原 Actions run/attempt/artifact；只复用已完成 task，partial SQL 从已接受的 cursor 延续，不能重复发布前缀。[S07]

`todo`：把 mdd 的 engine build、adapter schema、capability digest、compat profile、snapshot source-set digest、facts/cache schema、column schema 加入 checkpoint version。旧 checkpoint 不自动跨 engine 升级。内存 dataset/query ID 不当作跨进程持久句柄；要么有经校验的持久结果/计划续跑协议，要么明确不可恢复。新 process 可以重新执行必要的只读计划，但不能重新接纳/发布已封存前缀，也不能改变 source 或将 prefix 与新结果拼接。

### 8.3 路径与缓存职责

现有 `hostlab.STATE` 为仓库下 `runtime/hostlab`。路径表仅表示明确责任，不授权清理真实用户数据。[S01][S08][S09][S10][S16]

| 路径 / 层 | 当前含义 | 迁移要求 / 状态 |
|---|---|---|
| `runtime/hostlab/samples/<apk_sha>/base.apk` | 下载/复制后校验的精确样本，prepare.lock 控制准备 | `todo`：由 HostLab 提供受校验 SourceSet；引擎不接管下载 token |
| `runtime/hostlab/dexq-cache/` 或 `DEXQ_CACHE_DIR` | legacy SQLite 索引；旧 key 为 schema+path+size+mtime 的 SHA1 前缀 | `todo`：保留旧空间；新索引不能用同 key，也不能据它证明内容相同 |
| `runtime/hostlab/reports/<version>/<sha-prefix>/<stamp>/` | 审计 TSV、gate 日志、summary | `todo`：primary 与 shadow 分目录；只完整授权 primary 可进入发布路径 |
| `runtime/hostlab/remote-output/` | result/job/checkpoint/resources 等 artifact 内容 | `todo`：manifest 标注 engine/profile，沿用大小与允许文件类型 |
| `runtime/hostlab/analysis-schedule/`, `remote-requests/`, `remote-job-map/`, `version-matrices/` | 受控请求、队列、恢复、任务状态 | `todo`：不得当 engine cache；unknown dispatch 继续先查证 |
| `runtime/hostlab/artifact-cache/<scope>/<run>/attempt-<n>/` | 官方 archive hash + 本地文件摘要验证后的结果 | `todo`：不同 attempt/profile 不互认；旧坏缓存隔离，不覆盖为成功 |
| `runtime/hostlab/source-snapshots/<sha>/context.json` | BIL 模块源码快照/说明绑定 | `todo`：与 APK byte snapshot 分开命名与校验 |
| `runtime/hostlab-prepared/` | CI 依赖运行时缓存 | `todo`：engine build 与 Python 依赖 fingerprint 分别固定 |
| 拟定 `MDD_CACHE_DIR` 下按 schema/engine/source digest 分层 | 新的内容寻址字节、事实、索引/结果缓存 | `todo`：新命名空间、manifest、原子提交、lease/配额/淘汰；从未完整提交的缓存不得成为完整负证据 |
| 拟定独立 shadow workspace/cache/result root | 诊断候选实现 | `todo`：不能污染生产 hit rate、sealed checkpoint、发布文件或完成任务复用 |

内容身份必须绑定输入集合而不仅单个 APK：明确顺序、重复输入处理、物理成员、逻辑 DEX、输入 SHA256 与 source epoch。持有 fd 或 mmap 并不自动使可写文件不可变；采用已经证明不可变的快照/受控副本或明确的变更检测策略，读取失败/变化后使结果无效。无需为了迁移反复复制已获不可变保证的同一字节，但不能以 path+mtime 替代完整身份。

现有任意 raw SQL 不做完成结果自动缓存；结构化等价请求已有 24 小时 complete reuse、批内非 query memo 与 verified checkpoint。新引擎需要证明新缓存带来什么增量，不应再次把这些现成机制记作新增收益。[S03][S08]

## 9. 远端集成与 shadow 副作用隔离

现有 workflow 名为 **Host APK analysis**，analysis job 固定 runner checkout、只读仓库/Actions 权限；publish 是独立 job，只在相应完整审计/AI 操作触发。Actions 已有 concurrency queue、cancel-in-progress=false、依赖 cache、可选原生安装、限定 artifact 上传。[S17]

`todo` 迁移仅在批准的 provider 路径插入 mdd：增加可验证 build manifest 与 capability 检查；必要依赖失败时必须与请求策略一致；固定样本 SHA/revision、runner revision、模块 source snapshot 继续绑定。不要把 `continue-on-error` 扩展到完整性失败，也不要在 native worker 中保存云/AI 凭据。保留 child_environment 的敏感环境变量剥离与 allowed roots。

Shadow 流程必须遵循以下顺序，而不是把用户的提交 API 调用两次：

1. primary 请求完成身份解析，冻结同一个输入/源码/规则/参数 manifest；单次获取样本，验证后为两个独立 worker 提供只读 snapshot 视图。
2. B shadow 使用独立 session、cache、TEMP workspace、result root、query IDs 和资源预算。不得写 primary report/checkpoint/queue、执行第二次 dispatch、调用 AI、发布 artifact 为正式结果、改变完成缓存或自动回复外部工具调用。
3. primary 与 shadow 各自记录实际 engine/profile、source/coverage 与完整输出。shadow 失败只产诊断记录并阻止候选晋级；不能覆盖 primary。primary 的 SOURCE_CHANGED/完整性失败不能被“shadow 看起来成功”洗成成功。
4. 对需要有序的结果严格比较顺序；只有声明为 multiset 的证据可排序，仍保留重复。忽略列表必须显式版本化，仅容许时间、临时 ID 等非语义字段；来源映射、NULL、offset、flags、指纹不在忽略列表。
5. 差异记录保留最小输入身份、SQL/typed plan、原始响应、期望/实际 count/hash、首个不同值、error、coverage、阶段时间和复现命令；不能只写“diff failed”。
6. 正确性 shadow 可在独立资源预算下并行；性能 A/B 必须明确隔离并交替顺序，不能让 shadow 争用 CPU/IO 后仍把结果当无干扰基准。

## 10. 任务 DAG 与工作包

以下全部为 `todo`。这些是主计划 **M5 HostLab 等价切换、M6 性能/门禁复用/持久缓存** 的适配器工作包展开，不是另一套平行主阶段：契约/基线输入来自 M0，输入快照依赖 M1，facts/指令依赖 M2，SQL/typed IR/virtual-table 实现归 M3，核心协议归 M4，完整关系/资源/Smali 归 M7，最终平台与发布回滚归 M8。这里的任务只实现 HostLab 绑定、语料与验收，不能另写一份核心 parser/SQL/资源引擎。

主任务族的关联为：`MDD-050..055` 使用本节的 provider、规则、surface、分页、shadow 与 runner 工作包；`MDD-060..065` 使用独立计时、typed batch、门禁共享和持久化工作包；其余章节只作为上述核心前置阶段的输入/验收要求。具体一对一分配由主计划决定，不凭本表修改其任务含义。

每个工作包须独立可审查；实现文件位置为建议输出，不表示已创建。不得直接修改生产默认分支、派发私有云任务或推送部署来替代本地/fixture 验收；具体仓库变更按主工程提示词的工作流执行。

### HL-01 — 固定可重放契约与 workload 清单

- 状态：`todo`。依赖：固定 HostLab SHA、已有 E01–E06；不依赖 DexMeguviz。
- 输入：三层工具 schema、Q01–Q16、已有 20 字段比较器、两个真实 historical artifact 与授权可重放样本清单。
- 输出：`contracts/hostlab-v1/` 的工具/CLI/request/response/error/schema golden；`corpus/hostlab/manifest.json`，包含每条语料来源、hash、模式、是否完整、期望类型/顺序/重数；不提交私有 APK。
- 完成证据：自动清单覆盖 12/8/12 三层真实名称；17 表最低列与 wildcard 完整 schema 有断言；正确/失败/分页/资源-only/多输入样本均有身份。
- 失败与回滚：发现源码 SHA/结果版本不同则停止合并，保留原 evidence；不修改旧 baseline 补成一致。

### HL-02 — A0/A1/A2 基线执行器与计时范围

- 状态：`todo`。依赖：HL-01；可以与核心开发并行。
- 输入：固定二进制、机器/线程/缓存策略、同一冻结 workload；已有研究作为参考，不替代新轮次。
- 输出：版本化 benchmark manifest、逐轮 paired JSON、嵌套 wall-time span、CPU/IO/RSS 独立指标；完整端到端与输出等价验收命令。
- 完成证据：A0/A1/A2 比较从相同输入和结果契约起步；保留原始日志、失败轮和真实顺序；所有新增计时不重复相加；私有样本未获执行条件时明确 `todo`。
- 失败与回滚：数据不等价先判失败，不选最快一轮；保存证据，不自动改查询减少工作。

### HL-03 — Provider 与协议协商层

- 状态：`todo`。依赖：HL-01、核心 `mdd.capabilities.v1` 草案。
- 输入：旧 schema 1 的 backend/dialect/operation、完整安装身份、mdd profile。
- 输出：HostLab adapter provider registry 与新 request schema/显式协商入口；独立 `meguvizdexdash` 安装与版本清单；旧 CLI 与调用方不变时维持原 provider。
- 完成证据：强制 sqlite/dexsql 请求不被暗换；meguvizdexdash 显示真实 build/profile；不支持功能从 plan 阶段可见；安装器坏 SHA 不可用。
- 失败与回滚：未握手/版本不兼容按错误分类处理；恢复路由配置到原 provider，保留两个安装目录。

### HL-04 — 完整性与错误适配

- 状态：`todo`。依赖：HL-01、HL-03、核心结果/error schema。
- 输入：坏 DEX、缺成员、source mutation、超时/取消/配额、歧义、错误页、未知能力用例。
- 输出：三态 coverage 到 HostLab partial/complete 的显式映射；typed error adapter；fallback policy 与审计日志。
- 完成证据：仅 Unavailable/明确 Unsupported 的允许路径发生 fallback；其余失败不产生 MISSING/负缓存/complete；指定后端和必需 B corpus 不靠 fallback 通过。
- 失败与回滚：未知 error 默认 fail；禁止 broad catch 后当空结果；保留原异常和 source identity。

### HL-05 — SourceSet、snapshot 与新缓存命名空间

- 状态：`todo`。依赖：HL-01、HL-04、核心 snapshot owner/lifetime API。
- 输入：单/多输入、同 path 同 size/mtime 换内容、重复 ZIP 成员、041 逻辑 DEX、resource-only archive。
- 输出：受校验 SourceSet adapter、manifest/epoch、cache key 与原子 publication、lease/清理配额；与旧 dexq-cache 分离。
- 完成证据：file/pool ID 正确映射；缺成员无静默接受；旧 session 不读取新源；未封存缓存/partial facts 不被当完整；断电式中断后不污染旧可读缓存。
- 失败与回滚：候选缓存 quarantine，回到只读输入重算；只淘汰自有 namespace，不删用户样本/旧索引。

### HL-06 — 17 表与 SQL/typed IR 契约验收

- 状态：`todo`。依赖：HL-01、HL-03–HL-05、核心 facts 与 ADR-002。
- 输入：Q01–Q16、表列/单位、SQL operator corpus、外部通用 SQL 语料。
- 输出：面向 M3 已实现的 typed IR 快速路径与只读 SQLite virtual-table 桥的 HostLab adapter/语料验收；固定 SQL 引擎版本，按 profile 公布已验表/算子与 wildcard schema；不在 adapter 另建 SQL 内核。
- 完成证据：全部必需 audit 查询完整结果/重数/类型/顺序等价；EXPLAIN/trace 能证明候选/事实读取；没有全量 ETL 偷换架构；unsupported 必须是明确拒绝。
- 失败与回滚：ADR-002 保留差异与替代方案；未通过的 profile 不注册；必要 Q 不通过则 audit milestone 不通过，不能回旧引擎后称成功。

### HL-07 — 12 个原生 MCP 工具适配

- 状态：`todo`。依赖：HL-03–HL-06，以及核心 Smali/Manifest/资源能力按各工具分别到位。
- 输入：12 工具完整 schema、生命周期 golden、默认/compact 双表示与错误语料。
- 输出：MCP compatibility adapter、schema introspection、typed envelope normalizer、工具功能矩阵及可用能力声明。
- 完成证据：每个工具至少正常非空、空、边界/分页、invalid、quota/cancel 用例；decode/资源不能用 mock 空值充数；未实现行维持 todo，最终完整替换必须全部通过。
- 失败与回滚：关闭对应能力/profile；旧 provider 保留，不自动回退隐藏协议错误。

### HL-08 — B0 原消费契约路径

- 状态：`todo`。依赖：HL-04–HL-06、核心独立 CLI/query API。
- 输入：固定 native_cli 的 shape/data/marker、完整 str/None、deadline 和 row/byte guards。
- 输出：明确选择新 engine 的 compatibility CLI/session；保持 HostLab 消费代码和输出契约的 B0 实验路径。
- 完成证据：同一完整 query、全量 rows/hash、同线程/源/缓存策略；会话初始 inventory 与退出逻辑仍可核查；结果不截断。
- 失败与回滚：单独 provider flag 切回原引擎；不改已有 stdout parser 接受坏行。B0 收益只称“保留接口的替换模式收益”，producer 实现也变化时不能自动归因纯核心。

### HL-09 — B1 typed batch 消费与回压

- 状态：`todo`。依赖：HL-03–HL-07、核心 `mdd-wire/1`/batch owner API。
- 输入：同 Q corpus、大批量长值/NULL、跨批生命周期、取消/关闭、队列预算。
- 输出：typed batch iterator 与 HostLab row/graph adapter；按列/批消费、必要时延迟 Python dict 物化；固定 schema/NULL/整数宽度与字符串编码。
- 完成证据：真实 producer+OS pipe/SDK+consumer 联合墙钟与全量等价；队列有界、借用内存不越生命周期、错误不丢；组件回放结果不得冒充完整路径。
- 失败与回滚：回到已验 B0 或明确选定旧 provider；不能混合同一 session 两种未协商 wire format。

### HL-10 — structural 与 27 FEATURE adapter

- 状态：`todo`。依赖：HL-06、HL-08；HL-09 可作为优化分支。
- 输入：native_graph、native_rules、audit_catalog、EXPECTED_FEATURES 与 MISSING/PARTIAL/AMBIGUOUS 样本。
- 输出：保留 BIL 规则的 adapter；descriptor/signature/继承 facts 从通用核心取得；catalog/rule hash 继续显式绑定。
- 完成证据：27 FEATURE 全集、状态/detail/discoveries、重复定义处理等价；没有把 BIL package literal 编进 mdd-core；错误输入不转功能未命中。
- 失败与回滚：按规则/查询定位差异，回到原 adapter/provider；不修改候选规则掩盖核心语义差异。

### HL-11 — surface 与原始指纹 adapter

- 状态：`todo`。依赖：HL-05、HL-06、HL-08；HL-09 提供 B1 批路径。
- 输入：native_surface、surface_workers、audit_common；代码区间/顺序/资源定义与跨版本 golden。
- 输出：通用 facts/batch/raw byte view + HostLab 分类/summarize；可复用的 fingerprint 算子，不改原 profile 指纹语义。
- 完成证据：类/字段/方法、调用重数、协议、原代码/资源 fingerprint、changes/resource_changes/verdict 全量等价；超界/041未支持等明确拒绝。
- 失败与回滚：比较原始坐标与首个差异，不将 bytecode hash 换成便宜摘要；从 B1 回已验 B0/旧路径只在显式切换后重新执行。

### HL-12 — Python 门禁共享事实的第二阶段改造

- 状态：`todo`。依赖：HL-05、HL-10、HL-11；**不是第一阶段 37% 目标的隐含收益来源**。
- 输入：独立 intake/home wall-time、完整日志、同 snapshot 所需 facts 与源码顺序。
- 输出：门禁 adapter 或等价函数移植，共享 immutable source/facts；保留原 fallback 工具作为开发对照。
- 完成证据：两 gate 退出码/全部输出语义与覆盖一致；省去的重复 parse/hash 计入独立新窗口；有具体前后秒数，不能拿外层混合残差全额充当节省。
- 失败与回滚：继续运行原门禁，保留完整性；单独关闭新 gate，不改 FEATURE schema。

### HL-13 — 分页与 snapshot-bound cursor

- 状态：`todo`。依赖：HL-05、HL-07。
- 输入：QueryPages 的 schema/count/SQL/offset 约束、SQL LIMIT、重复行、NULL、跨页源改变、大页输出、Smali/resource 续页。
- 输出：mdd cursor 到兼容 offset 的明确映射、typed page envelope、稳定排序和 token 校验；page budget/backpressure 停止原因。
- 完成证据：无漏行/重行/跨源混页；同 SQL 同 schema 同 count 但变内容也失败；只接纳完整页；output_too_large 缩页不换后端或吞错误。
- 失败与回滚：停止并保留已接纳的 partial 页；无有效 snapshot 身份不继续，不发明 next_offset。

### HL-14 — checkpoint 与恢复版本升级

- 状态：`todo`。依赖：HL-04、HL-05、HL-13。
- 输入：sealed checkpoint、run/attempt/artifact、engine/capability/schema 绑定、已完成/partial task。
- 输出：新 checkpoint version 与受校验 importer；明确跨进程 cursor 寿命、续跑策略与旧版本拒绝规则。
- 完成证据：升级/变源/变 query/变 engine 不误复用；complete task 不重复执行或发布；partial 前缀不重复接纳；未知 dispatch 不恢复成新请求。
- 失败与回滚：保留原 sealed 文件，不原地改版本；明确新任务/显式重跑由调用者决定。

### HL-15 — 远端 runner、artifact 与 12 个编排工具

- 状态：`todo`。依赖：HL-03、HL-07、HL-14；先本地/fixture 模拟验证。
- 输入：现有 workflow、remote_schedule、version_matrix、runner_worker、artifact/snapshot contracts。
- 输出：选定 mdd build/profile 的安装配置、plan_ci 与 runner adapter、结果 manifest；保留 queue、固定/自适应组策略和原 artifact trust chain。
- 完成证据：plan/status/result 不派发；submit/recover 幂等和 unknown 状态不重放；每 sample 的 source/engine 绑定完整；资源预算/退出/partial 与真实 child state 一致。
- 失败与回滚：固定 runner revision、配置级恢复旧 provider；新旧 output/cache 隔离；取消/重试遵循原任务语义，不自行增加云任务。

### HL-16 — 无发布副作用的 shadow comparator

- 状态：`todo`。依赖：HL-04、HL-05、HL-07、HL-10、HL-11、HL-13；远端场景额外依赖 HL-15。
- 输入：同一 immutable job manifest、独立 A/B workspace、全量结果与允许归一化规则。
- 输出：shadow harness、结果差异包、禁止 dispatch/AI/publish 的运行模式与结构化验证记录。
- 完成证据：同输入同语义、完整/partial/错误均比较；mutating side effects 被隔离；故意制造不同来源、丢重复引用、错 NULL、错误指纹时 comparator 确实失败。
- 失败与回滚：候选留在 shadow，primary 不受影响；保存差异、阻止 rollout，不把不一致字段加入 ignore list。

### HL-17 — 完整性能验收与真实根因定位

- 状态：`todo`。依赖：HL-02、HL-08–HL-11、HL-16；若包含 gate 优化则增加 HL-12。
- 输入：A0/A1/A2/B0/B1 的完全等价 workload、真实 S/F/O 时间边界、资源 telemetry。
- 输出：逐轮 paired 数据、完整耗时与 S/F 阶段改善、engine/producer/consumer/指纹/gate 分项、成本与内存、失败范围及瓶颈归因。
- 完成证据：第一阶段目标按第 11 节；必须同时报告相对 A0 与最佳已验 A1/A2 的增量；新增工作/额外验证成本计入真实总时间；不给未测 p95 或整体 RSS 降幅。
- 失败与回滚：正确但不达性能门槛可以保留实验实现，不切生产默认；按 profiling 调整方案，不减少证据或跳过 gate 达标。

### HL-18 — 完整职能切换与可恢复发布

- 状态：`todo`。依赖：HL-07、HL-10、HL-11、HL-13–HL-17；HL-12 是否纳入该版本由明确发布范围决定。
- 输入：12 工具完整矩阵、全部必需 audit 0 fallback 证据、安装/许可/版本清单、支持平台、运维与恢复说明。
- 输出：候选 release artifact 与验证摘要、默认路由变更草案、分批切换和 rollback 手册；实际部署是独立获授权动作。
- 完成证据：无 DexSQL 的独立安装可完成发布声明的所有必需功能；不支持项被准确声明且不能覆盖完整替换所必需的工具；保留可重放失败包、迁移/卸载路径。
- 失败与回滚：停止接受新 B 请求、等待/取消已有请求按协议处理，再切回固定旧 provider；不把 B 的 session/cursor/cache 当 A 的复用；保留 forensic 证据。

## 11. 基线与性能门槛

| 基线 | 精确定义 | 能报告什么 |
|---|---|---|
| A0 | 固定 DexSQL 0.1.0 + 固定当前 HostLab（已含 64 KiB、范围筛选、session reuse 等） | 相对今天生产实现的改善 |
| A1 | DexSQL 0.1.1 + 经等价验证的原 HostLab 路径 | 上游升级收益；公开单查询已有局部证据，完整 BIL 仍需实测 |
| A2 | 最佳已验可用的机器接口/表示/配置优化，仍使用现成引擎 | 现成方案的合理对照；compact/typed/包装层优化不自动归给自研 |
| B0 | 自研实现，保留原 SQL/CLI/MCP 表示和 HostLab 消费契约的比较模式 | 同接口替换模式的整体收益；producer/parser/formatter 也变时不等于纯 core 归因 |
| B1 | 自研核心 + typed batch + HostLab adapter/必要聚合改造 | 完整职能替代的实际收益 |

第一阶段 **约 37% 降时是 B1 目标，非成绩**。其来源是固定历史 A0 的两个完整阶段 S=structural、F=surface 各快 2 倍，其它区间保持不变：

```text
E_new = P + R + O + S/2 + F/2
target:   24.441474 + 13.663421/2 + 56.525247/2 = 59.535809 s
baseline: 22.859099 + 11.911596/2 + 50.801524/2 = 54.215659 s
```

对应约 37.09% / 36.64% 降时，预算可口头称约 60/55 秒。P 是显式 prepare，R 是 native 内未分相位余量，O 是 native 外混合残差；不能把 O 全称两个 Python gate，也不能把 lazy 解析全部划入 P。S/F 包含引擎、传输、Python 与指纹，所以“核心快 2 倍”不等于 S/F 各快 2 倍。新校验、数据复制、机器接口或调度增加的时间必须加回新 E。[E1][E3]

完整对照至少在两个已有实际 APK 与更小/大型多 DEX、边界语料上进行。相同来源、线程、资源、规则、缓存模式，交替执行至少 10 轮，报告 paired 中位和观察区间；尾延迟单独充分采样。只要 A1/A2 在同完整 workload 上更快，B1 的新增收益必须重新以该基线为分母。A0→A1、A1→A2、B0→B1 的百分比不能相加。

门槛次序固定：**来源/覆盖与功能正确 → 全量证据等价 → 资源与生命周期可控 → 完整时间门槛 → 部署切换**。这不是要求等整个项目写完才测性能；HL-02/HL-08/HL-09 及每个关键算子都应尽早采样，但任何局部成功只能报告自己的范围。

## 12. 给工程 AI 的单任务执行格式

每个任务开始时输出本任务 ID、固定输入 hash、已满足依赖、要改的 adapter/core 边界和本次验证范围；不要重写整个计划。执行后产出以下可审查记录：

```text
Task: HL-xx
Status: todo | existing evidence
Phenomenon: 用户可观察的行为/当前瓶颈
Evidence: 固定源码/原始响应/完整样本身份/测量窗口
Root cause: 已证实部分；未证假设另列
Change: 具体接口/数据结构/查询/生命周期变更及理由
Failure policy: 哪些错误必须fail；哪些显式策略允许fallback
Validation: 完整结果、负例、资源、配对性能；精确覆盖范围
Rollback: 版本/路由/缓存/正在进行请求如何恢复
Remaining: 未完成的工具、格式、平台、根因或性能门槛
```

`Status` 在此规划包中保持上述两态；后续实际工程可以由主工程提示词另定义状态机，但不得把本文 todo 复制为已实现。证据必须是运行结果或源码推导，不能是“下一步会测试”的承诺。每项完成需要代码、可复放输入/命令、原始输出、判断标准与已知失败范围。遇到实际差异，先保留复现与解释，再提出修复；不改黄金结果迎合实现，不用 mock 输出代替工具能力，不借全程 fallback 证明引擎完成。

## 固定来源

- [S01] [HostLab 固定源码与状态路径](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/hostlab.py#L1-L26)
- [S02] [固定 DexSQL 安装/校验](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/install_dexsql.py#L15-L99)
- [S03] [batch、Session 与完整性](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/analysis_batch.py#L51-L412)
- [S04] [原交互 CLI](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/native_cli.py#L18-L195)
- [S05] [surface 查询、范围与指纹](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/native_surface.py#L11-L147)
- [S06] [稳定分页与字节预算](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/analysis_paging.py#L9-L226)
- [S07] [sealed checkpoint](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/analysis_checkpoint.py#L45-L240)
- [S08] [调度、精确复用与未知派发](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/remote_schedule.py#L101-L232)
- [S09] [源码 snapshot transport](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/snapshot_transport.py#L72-L111)
- [S10] [legacy dexq 八工具与 SQLite schema](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/dexq/server.py#L88-L466)
- [S11] [remote MCP 十二工具](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/remote_mcp.py#L176-L468)
- [S12] [dexq CLI 全命令与路由](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/dexq_cli.py#L24-L154)
- [S13] [完整 native audit](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/native_audit.py#L15-L66)
- [S14] [Graph 查询、Signature、跨 DEX 身份](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/native_graph.py#L123-L292)
- [S15] [native 后两个门禁与报告](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/analyze.py#L281-L336)
- [S16] [runner 操作分派与绑定](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/remote_job.py#L169-L312)
- [S17] [固定 workflow](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/.github/workflows/host-analysis.yml#L1-L182)
- [S18] [request 验证、后端选择及 SQL 模板](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/analysis_plan.py#L27-L187)
- [S19] [native rules](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/native_rules.py#L21-L140)
- [S20] [27 FEATURE 与覆盖缺口](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/analysis/run_intake.py#L28-L93)
- [S21] [原资源字节指纹](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/audit_common.py#L6-L17)
- [S22] [原全量等价比较器](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/verify_audits.py#L25-L99)
- [E1] [原 Actions run 40067936875](https://github.com/jichuo1/innocent-lab-host-analysis/actions/runs/40067936875)；包内 `evidence/hostlab_verification.json` 保留原 JSON，SHA256 `bf4ca0cd3df35dab13ed1a83dedf92e5b6dfa485e4d48611d424cf8462b01f7d`。完整阶段抽取见 `evidence/hostlab_measured_basis.json`。研究原路径为 `/workspace/scratch/acc0e5058f47/research/quant_v3/artifacts/40067936875/remote-output/verification.json`。
- [E2] 包内 `evidence/hostlab_public_pipeline.json`，SHA256 `9f58b19438a5a120c457b72f1b850c9faf54df128be5120fd6a315ccfd915df2`；输入为 [NewPipe v0.28.6](https://github.com/TeamNewPipe/NewPipe/releases/tag/v0.28.6)。原执行目录 `/workspace/scratch/acc0e5058f47/research/quant_v3/`。
- [E3] 包内 `evidence/measured_phase_model.json`、`evidence/decoder_microbenchmark_results.json`、`evidence/decoder_public_apk_results.json`。原解释报告 `/workspace/scratch/acc0e5058f47/research/quant_v3/HostLab_DexSQL_Quantified_Performance_20261026.md` 与 `decoder_microbenchmark_report.md`：已研究的目标与组件范围，非已实现 B 引擎。
- [E4] 包内 `evidence/compatibility/0.1.0/mcp-records.json` 与 `evidence/compatibility/0.1.1/mcp-records.json` 保存实际 tools/list。原 0.1.1 发现记录和嵌入说明在 `/workspace/scratch/acc0e5058f47/research/dexsql_blackbox/mcp-discovery.json` 与 `embedded_docs/mcp/`。完整 schema 的正式契约和回归 corpus 应由 HL-01 从这些原始记录生成，而不是靠本表省略参数重新发明。
