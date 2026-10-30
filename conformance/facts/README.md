# MDD-026 独立事实一致性验证

本目录只组合公开事实 API 和独立小型 oracle，不提供生产 catalog、SQL 关系适配器或事实完整性签发器。`required-columns.json` 覆盖冻结的 17 个必需关系、156 列，分别记录 native 原子来源和兼容关系装配状态。原子已存在不等于旧关系已装配；旧关系尚未装配也不额外成为 MDD-026 的前置条件。

运行 `python -O conformance/facts/reproduce.py`，结果写入 `artifacts/mdd-026/`。脚本在不修改任何 workspace crate 的前提下，以 Cargo 的实际 artifact 清单链接独立 `native_probe.rs`。探针拒绝超过 1 MiB 的输入，只处理列出的八个微型场景、九次 DEX 来源出现，不读取私有 APK、不测性能。

验证包括：

- 逐来源 UTF-16 code units、原始 MUTF-8、类型与有序 proto/方法参数。
- 类、接口、字段和方法的引用/定义、group ordinal、flags、body 分类。
- 全物理 code_item 起点、头字段、code-unit/byte 范围、完整 opcode/pc/width 原子。
- 每个定义方法的原始 insns SHA；native/abstract 无 body 不等于空字节。
- 独立 Python 小指令 oracle 的位置化引用以及四个完整关系，保留重复站点。
- 独立注解 oracle 的四个必需关系，核验全部列、类型、NULL 和重数。
- 每个合法目标的 indexed/scalar 返回值相等；同内容重复输入仍有不同 occurrence，跨来源目标拒绝。
- 合法非标量字符串仍保留 raw facts，普通 UTF-8 行拒绝；坏注解层不能返回空成功；参数 prototype-position Unknown 不与已编码 slot 完整性混同。

当前范围内检查实际通过：331 次 indexed/scalar 对照、43 次完整关系比较。它们不签发 MDD-026 整体完成。索引实现和 coverage 签发器由另一个单写者实现；还须实际验证 lazy 首次并发、失败重试、required_layers/scope_id 三态、请求列/子范围及失败阻断。G1 parser/sanitizer、G2 QueryIR/SQL、MDD-032 冻结兼容 schema 和后续 HostLab 完整请求分别验收。

首次新增类型检查曾错误地只接受有限 JSON number；冻结注解契约对 Float64 列明确允许 `NaN`、`Infinity`、`-Infinity` 表示，原位模式保留在 EncodedValue。验证器已据该既有契约修正，生产事实与 golden 未改。

所有必需 Python 检查使用显式 `require`，不依赖会在 `-O` 消失的 `assert`。源码、原始命令、stdout/stderr、输入 SHA 和探针终态可追溯；没有固定输出或默认 skip。回滚仅撤回本目录及对应 `artifacts/mdd-026/` 的本轮新增文件，不修改其他模块或既有分层原始证据。
