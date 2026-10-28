# MeguvizDexDash 当前状态

更新：2026-10-29（Asia/Shanghai）。唯一任务图：tasks/backlog.json；当前产品仍在实施，所有产品 profile admitted=false。

## Checkout 与交付

工程目录 D:\MeguvisDexDash（保留目录原拼写）。私有远端 https://github.com/jichuo1/MeguvizDexDash；当前审查分支 codex/m2-facts-20261028，草稿 PR #1。main 当前 abdcdf4；审查分支最新已推送检查点 e56db3e 的 Windows/Linux 原生 CI 均通过，各108项含 compile-fail。工作区中后续026、034和031的改动尚未提交或推送，不能将该 CI 结果归于它们。

大范围 push main 曾被自动审批以缺少本次默认分支推送明确授权为由拒绝；后续采用独立分支和草稿 PR。没有合并、默认后端切换、部署或正式发布。

原工程包 SHA-256 b5f2f3859a5a7753f83f8edc24c73ce15781075afb899e4e63b274fdcc161844，原始规格提交 3bbf1088137e70c5d3d722534a5eeab8b69a596c；handoff/original/MeguvizDexDash 保持不变。原包 verify_kit/recompute_targets 实际通过（56 文件、23 历史证据、51 DAG 任务）；这些不是引擎测试。

## 已验收的实现范围

- M0：MDD-001/002/003/004/006 已完成各自验收；005 尚未完成。
- M1：MDD-010/011/012/013/014 已完成限定任务范围，包括不可变快照、逻辑出现次数、ZIP32/ZIP64 物理成员、生命周期与真实 worker 故障。012 曾重新打开补齐 ZIP64，52 向量及 65,535/65,536 成员边界已重验。
- M2：MDD-020/021/022/023 已完成字符串/类型/原型、定义、注解与编码代码布局。020 曾因内部 item 引用反例重新打开，已用物理起点、合法 orphan、SDK 正反例与公开样本重新验收。Ready facts 对外只读。
- MDD-024：9 引用测试、18 手工 fixture（11 所需层成功、7 真损坏）、43 个固定 A0 完整小关系比较通过。公开 NewPipe 两 DEX 共 509,322 operand sites 完整读取。精确声明查找不等于运行时分派/继承解析；合法非 scalar 文本保留 UTF-16，拒绝有损 UTF-8 投影。
- MDD-025：原始方法体、资源和 Manifest 所需事实验收完成。公开 55,763 方法、8,540 类聚合 recipe、792 资源逐项/摘要对齐固定 A0、Python 和原 HostLab 规则；76 Manifest 向量、AAPT2 完整树及 A0 六页结果通过。方法无 body 与空 body 区分，Manifest 与资源持有同一 Arc，源改写/重命名/释放后仍保持同快照证据。见 artifacts/mdd-025/raw-evidence-conformance.json。

公开样本为官方 NewPipe 0.28.6，10,885,562 字节，SHA-256 e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58。APK 位于 ignored artifacts/local/inputs，不进入 Git。上述均非 ART 完整验证、完整 HostLab 替代或性能资格。

## 当前推进与阻塞

MDD-026 的索引和三态 coverage 已有测试证据，但逐列事实验收尚未完成；MDD-030 类型化 IR/基础算子已完成Windows限定范围验收：7单元+2compilefail、36查询case、20LIKE、322正/12负Base64均实际通过，源码稳定且根复验通过。031 SQL桥与034预算/取消/终态的前置依赖已满足。未通过的 Methods 代码列、参数文本编码与参数注解 slot Unknown 均须显式阻断相应查询，不能填零/空值制造完整结果。

解析安全独立 fuzz workspace 已实际完成 10,400 次本地 mutation、2 Rust 与 2 Python oracle/驱动测试、严格 Clippy。b29933d 两平台原生 CI 已通过，原始十份命令记录均 exit0。Linux ASan run40692557250 也真实通过：正控制非零检测到预期越界，六个各 15 秒目标共 2,426,570 次执行、无 crash 文件或超时，原 ZIP 的 GitHub 摘要及每份日志计数/锁参数均独立核验。见 artifacts/conformance/parser-safety/ci-readback.json。G1 未签发；固定预算不是完备证明，测试 nightly 不改变发布 stable 1.99.0。

两个授权 APK 已核验完整 SHA/长度和 33/35 DEX，原位置未改变且不入 Git：9161100=226,519,215 字节/41efb1c9acb07badab5296953fb3da1def6925e2b34662120ca96df9d17bbfb2；9170100=243,687,778 字节/f0f880e841d017db335b3919e6d4792961f2e08aa9993da661b626d52cfcb955。实际路径及 mtime 前后核验见 artifacts/bootstrap/20261028/private-input-acquisition.json。两个私有输入另有实际受限 CLI 成员/头部检查通过：68 个 DEX 全为 037，进程树均清空，峰值 Job commit 623,386,624/676,052,992 字节；原始输出留在 artifacts/local，摘要为 artifacts/integration/20261028/private-headers-20261028T130804307935Z.json。该检查不含完整事实、业务审计或性能试次。

MDD-005 的固定 HostLab 驱动、A0/A1 身份、隔离 Python 环境及 Windows Job 监督器已就绪。2026-10-29 可用内存重新达到原定10 GiB准入后，已对两个授权输入各执行一次 A0 与 A1 完整静态资格检查；每份覆盖27 FEATURE、20组证据，零 fallback、完整交付、子进程树清空，同输入的20组结果全部相等。四次业务程序返回码均为1，完整运行与等价不表示业务审计结论通过。重新读取原始证据及身份见 artifacts/mdd-005/static-qualification-20261029.json；私有原始输出留在 artifacts/local/baseline-runs。项目代理在该时段暂停，但系统其他应用未隔离；本轮不是性能试次。A2 完整适配、正式配对测量和最强合格基线选择仍未完成，历史约37%/47%仅条件目标。

## 锁定与恢复

发布 Rust/Cargo 1.99.0，Windows x86_64 MSVC；Linux 同版本原生验证按不可变 CI checkout 单独登记。十项直接生产依赖均获用户批准：serde、serde_json、sha2、sha1、zip、rusqlite、getrandom、quick-xml、sqlparser、log；根 lock 目前46个外部 package。SHA-1 仅 DEX 兼容校验；来源身份 SHA-256。SQLite 3.53.2 只读虚表桥正在 MDD-031 实施，兼容性尚未验收。Python 本地 3.12.14，CI 3.12.10；依赖与许可证见 conformance/manifests/dependencies.json。

root 单写共享 Cargo/lock、exports、STATE/backlog/ledger/index 和 CI；026 索引/coverage、030 查询、独立全事实验证分开文件所有权。性能测量先暂停其它 CPU/IO 工作并取得真实资源窗口。并行检查点用 refresh_artifact_index.py --from-index 登记精确暂存 blob，再重建检查点运行 check_progress.py，不能混入活动文件。

恢复先检查 Git/任务/进程，不重建任务图。现有 BIL/HostLab 外部工作树、配置和用户修改保持原状。原始成功/失败记录保留；当前回滚为在审查分支创建范围 revert 提交，保留初始规格和失败证据，不 reset/clean/强推。完整审计、SQL、MCP、FFI、桌面、ARSC、正式发行与 MDD-082 性能资格仍未取得。

031 SQL桥正在实施，034预算/取消/终态限定机制已完成本机验收。用户已另行批准sqlparser0.63.0（仅std）与log0.4.34，独立探针实际构建/AST往返通过；根锁仅增这两包，无其他外部升级。两个私有Manifest完整树与原始属性逐项通过：2115/2119节点、5275/5291属性，含exact float32 bits、TYPE_REFERENCE零值与TYPE_NULL分开；首轮日志quota及显示比较失败原样保留，见private-manifest-captured-conformance.json。这些仍不代表完整HostLab审计或性能通过。

私有完整raw诊断另行在启动前被4GiB开发任务准入拒绝（并非正式基线阈值调整），没有开始编译或解析；后续独立WMI观察仅2404388KiB可用。失败记录private-raw-diagnostic-20261028T135952890645Z.json保留，不能推断引擎解析失败或性能结果。

MDD-026 已重新打开：独立复核发现资格脚本对17关系156列主要检查原子可用性声明，尚不能证明每列的字段/类型、NULL、顺序、重复性、来源及 raw 指纹均有独立证据；例如 dex_files.file_id 已有原生分配代码，但尚缺固定旧实现和全部来源场景的端到端逐列验证。已有219候选请求（55残余反例）、35 facts+4 compile-fail组件测试、11索引/coverage根测试及8场景43关系比较仍有效，69个兼容投影缺口仍明确阻断。原 conformance/manifests/hostlab-fact-qualification.json 保留为限定原生原子检查的历史记录，不代表 MDD-026 原验收完成。G1/G2、完整私有事实与 HostLab 资格仍未签。033正在只读预研，依赖031尚未完成，不先假解锁。

补充事实对照：合成样本中三个定义关系的21列与固定A0完整行多重集合一致，含错误编号、NULL和缺行负例；三个合成DEX的24个头字段与独立原始字节解码及A0单输入结果一致，含四个损坏/篡改负例。原始记录和回读分别为 artifacts/mdd-026/new-audit/definition-projections/readback.json、artifacts/mdd-026/header-audit/20261028T163754102728Z/readback.json。A0多输入编号和兼容关系装配仍未证明。

MDD-034 已根验收 done，范围是预算、取消和终态机制：Windows 本机 27 query、10 session、7 types 及2 compile-fail 测试通过，相关包严格 Clippy 通过；SQLite 双连接中断和独立子进程 deadline 探针通过。结果及源码身份见 artifacts/mdd-034/budget-and-terminal-states.json。生产 worker、MCP、FFI 和当前源码的 Linux CI 尚未验证；进程树隔离未由该探针证明。

MDD-031 SQL桥仍进行中：受限虚表、会话预算绑定、U64真值、USING和子串路径有本机测试；独立真值18例及固定A0/A1子串16例通过，合成Q15结果与SQLite一致。真实完整corpus、legacy适配及生产工作区内存绑定尚未验收。当前冻结工作区 Windows 离线测试161项、0失败/跳过，工作区严格Clippy通过，命令记录在 artifacts/integration/20261029/workspace-tests/ 与 workspace-clippy/；当前源码Linux CI尚待该检查点验证。
