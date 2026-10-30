# MDD-033 TEMP 政策前置实查

2026-10-28 在固定 Windows A0/A1 上实际执行。此目录只给后继 catalog 实现提供独立行为证据；MDD-031 尚未完成，MDD-033 仍未完成，所有 profile admitted=false。

最终完整运行：`20261028T150631618895Z/summary.json`。A0/A1 各 16 个独立 dataset、70 条 SQL，共 32 个 dataset/140 条 SQL。每个 dataset 都显式 close；各进程最后 `list_datasets` 返回空集、input_bytes=0、admitted_requests=running_requests=0。MCP Client 上下文顺序退出；额外 Windows 只读进程清点为零个 dexsql 进程，见 `process-readback.json`。没有强杀进程或修改业务配置。

固定身份：

- A0 0.1.0：SHA256 `f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448`。
- A1 0.1.1：SHA256 `602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6`；路径来自已验证的 baseline-manifest，未改 installer/source。
- 输入 `tests/fixtures/references/generated/classic-035.dex`：660 字节，SHA256 `076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8`，与既有 fixture manifest、MDD024 证据一致。
- 复用隔离 `artifacts/local/baseline-venv`、MCP 2.2.0 与 MDD005 已验证 Client/StdioServerParameters helper 模式。每个引擎单线程、最多一个 dataset、原生操作 1500ms、客户端调用 5 秒、单引擎上下文 45 秒限时。两个引擎串行，不进行测量比较。

## 两版相同的实查结果

| 政策 | 观察及准确边界 |
| --- | --- |
| 已有 TABLE/VIEW 的 `IF NOT EXISTS` | 成功，原值 1 保留。被忽略的新 body 引用 `never_defined` 也成功，说明该分支不绑定该 body 的未知名称。没有测试语法损坏的 body，不能推断跳过语法解析。 |
| TABLE 与 VIEW 同名、无 `IF NOT EXISTS` | 成功替换为新值 2，且替换后的对象种类生效：TABLE→VIEW 后 DROP TABLE 报 `use DROP VIEW to delete item`，反向同理。失败 DROP 后对象和值不变。 |
| TABLE 与 VIEW 同名、有 `IF NOT EXISTS` | 原值和原对象种类保留；请求定义的新种类不会覆盖原种类。 |
| 不存在对象的 `DROP ... IF EXISTS` | 成功，`kind=drop_definition`，空 DDL 行结果。 |
| 不存在对象的普通 DROP | TABLE 报 `no such table: absent`；VIEW 报 `no such view: absent`。 |
| DROP 的种类不匹配 | 无论是否 `IF EXISTS` 都失败，报 `use DROP TABLE/VIEW to delete item`；之后查询仍返回原值 1。`IF EXISTS` 不能吞掉种类错误。 |
| 新定义前向引用不存在名称 | TABLE、VIEW 以及两者加 `IF NOT EXISTS` 的四种形式都在 CREATE 时拒绝：`unknown relation \`future\``。随后查询 derived 报未知名称；创建 future 后 derived 仍未知，证明失败定义没有被发布、没有自动复活。 |
| 错误类别 | 上述实际语义错误全部是 `kind=invalid_query`、`stage=execute_sql`、`statement_index=0`；不属于 unsupported 或资源失败。 |
| DDL 结果 metadata | CREATE TEMP TABLE 和 CREATE TEMP VIEW 均实际返回 `kind=create_temp_table`。对象种类仍由后续 DROP 严格区分，不能仅凭该 metadata 推断 VIEW 被当作 TABLE。 |

这补齐了此前未知的 IF 条件、跨种类替换和 forward 引用时机；不推翻历史 `temp_dependency_drop_recreate` 的按名称重新绑定观察。组合结论是：**建立新定义时验证依赖；成功定义的依赖之后仍会按当前查询目录名称重新绑定**。这并不表示 CREATE 可以注册未解析的前向引用。

## 原始证据与回读

`A0/A1.observations.json` 保存完整工具参数、标准 MCP typed cells、错误、open/close 和最终 dataset 列表；`A0/A1.sdk-transcript.jsonl` 为完整 SDK 工具请求/响应序列，不冒称原始字节 wire transcript。原始 MCP 结果的 text/structuredContent 都保留。驱动没有暴露引擎最终 exit code，因此只声明 Client 上下文退出、零存活进程和数据集使用归零。

`verify_policy.py` 已实际在 Python `-O` 下 exit0：逐条核验每版 103 个工具调用、207 条 SDK transcript 记录、全部 SQL/顺序/错误/精确值/NULL/列 schema、每次 close 和最终使用归零；两版完整规范化结果相同。校验故意修改 close 收据也会失败。回读文件是 `policy-readback.json`。

重现命令（每次追加新的 UTC 目录）：

```powershell
& 'D:\MeguvisDexDash\artifacts\local\baseline-venv\Scripts\python.exe' -O artifacts/mdd-033/preflight/probe_temp_policy.py
& 'D:\MeguvisDexDash\artifacts\local\baseline-venv\Scripts\python.exe' -O artifacts/mdd-033/preflight/verify_policy.py
```

保留初次输入准入失败 `first-admission-failure.json`：驱动起初误抄了 A2 另一个样本的 SHA，准入门禁在启动引擎前拒绝；核对既有 660B manifest 后只修驱动，未改 fixture。第一轮 62 SQL/版也原样保留在 `20261028T150440953995Z`，第二轮只补跨种类替换后的 DROP 种类确认。

仍未验证：循环、语法损坏的 IF NOT EXISTS body、多语句原子回滚、跨 session TEMP 隔离、参考引擎目录 epoch、原生 MDD catalog/cursor、完整 HostLab corpus、私有输入和性能。没有修改共享 backlog/STATE/ledger/index 或任何生产文件；本目录是限定前置行为证据，不是任务完成或发布证书。
