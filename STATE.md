# MeguvizDexDash 当前状态

更新：2026-10-28（Asia/Shanghai）。唯一任务图：tasks/backlog.json；当前产品仍在实施，所有产品 profile admitted=false。

## Checkout 与交付

工程目录 D:\MeguvisDexDash（保留目录原拼写）。私有远端 https://github.com/jichuo1/MeguvizDexDash；当前审查分支 codex/m2-facts-20261028，草稿 PR #1。main 当前 abdcdf4；47fd432 检查点已在审查分支推送，两次 Windows/Linux 原生 CI 成功（40681784942、40681806497）。本轮新实现尚待同版本 CI。

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

MDD-026 的索引、三态 coverage 和 17 必需关系逐列独立差分正在实施；MDD-030 已满足图中依赖，类型化 IR/基础算子正在独立实施。未通过的 Methods 代码列、参数文本编码与参数注解 slot Unknown 均须显式阻断相应查询，不能填零/空值制造完整结果。

解析安全独立 fuzz workspace 已实际完成 10,400 次本地 mutation、2 Rust 与 2 Python oracle/驱动测试、严格 Clippy。Linux ASan 正控制和六个各 15 秒的 libFuzzer 有限 job 已准备待首次 CI；G1 未签发。测试 nightly 不改变发布 stable 1.99.0，也不把零 crash 视作完备证明。

两个授权 APK 已核验完整 SHA/长度和 33/35 DEX，原位置未改变且不入 Git：9161100=226,519,215 字节/41efb1c9acb07badab5296953fb3da1def6925e2b34662120ca96df9d17bbfb2；9170100=243,687,778 字节/f0f880e841d017db335b3919e6d4792961f2e08aa9993da661b626d52cfcb955。实际路径及 mtime 前后核验见 artifacts/bootstrap/20261028/private-input-acquisition.json。

MDD-005 完整固定 HostLab 驱动、A0/A1 二进制身份、隔离 Python 环境、Windows Job 受限子进程及完整结果证书技术准备已完成。根资源审查仅有 7,672,709,120 字节可用物理内存，低于预登记 10,737,418,240；未授予独占测量窗口，未运行私有完整审计或正式性能试次。不能调低阈值、终止无关进程或以公开小样本替代。历史约 37%/47% 仅条件目标，baseline-runs.jsonl 尚无正式试次。

## 锁定与恢复

发布 Rust/Cargo 1.99.0，Windows x86_64 MSVC；Linux 同版本原生验证按不可变 CI checkout 单独登记。八项直接生产依赖均获用户批准，当前根 lock 44 个外部 package：serde、serde_json、sha2、sha1、zip、rusqlite、getrandom、quick-xml。SHA-1 仅 DEX 兼容校验；来源身份 SHA-256。SQLite 3.53.2 捆绑只读虚表桥仍只完成 M0 实验，五项文本/方言差异由后续查询任务处理。Python 本地 3.12.14，CI 3.12.10；依赖与许可证见 conformance/manifests/dependencies.json。

root 单写共享 Cargo/lock、exports、STATE/backlog/ledger/index 和 CI；026 索引/coverage、030 查询、独立全事实验证分开文件所有权。性能测量先暂停其它 CPU/IO 工作并取得真实资源窗口。并行检查点用 refresh_artifact_index.py --from-index 登记精确暂存 blob，再重建检查点运行 check_progress.py，不能混入活动文件。

恢复先检查 Git/任务/进程，不重建任务图。现有 BIL/HostLab 外部工作树、配置和用户修改保持原状。原始成功/失败记录保留；当前回滚为在审查分支创建范围 revert 提交，保留初始规格和失败证据，不 reset/clean/强推。完整审计、SQL、MCP、FFI、桌面、ARSC、正式发行与 MDD-082 性能资格仍未取得。
