# MeguvizDexDash 拟定契约

这里的 JSON Schema 是供实现者使用的 **设计契约**，尚无已实现引擎。Schema 通过校验只证明文档形状与部分约束合法，不证明 DEX 解析正确、兼容已通过或性能已经达到目标。版本和语义依据 [核心架构](../docs/02_ARCHITECTURE_AND_CONTRACTS.md)；[验证规范](../docs/04_VALIDATION_AND_PERFORMANCE.md) 定义资格门槛。

## 文件与用途

| 文件 | 对象 | 用途 |
| --- | --- | --- |
| [result.schema.json](result.schema.json) | `mdd.result.v1` | 一次终态或分页请求响应；不是每批重复的流式帧 |
| [capabilities.schema.json](capabilities.schema.json) | `mdd.capabilities.v1` | 构建身份、格式、profile、通道、预算与 provider |
| [benchmark_result.schema.json](benchmark_result.schema.json) | `mdd.benchmark-run.v1` | 一次实际观测；必须保留身份、环境、完整性、逐项指标与证据 |
| [examples](examples/README.md) | 明确标为 example 的虚构数据 | 正常、分页、错误和未准入能力的协议形状示例 |

这些文件使用 JSON Schema 2020-12，`$id` 为 URN，不要求访问一个并不存在的项目网站。版本破坏性变化时新增 schema/profile 和迁移说明；不要就地改变已发布版本的含义。

## 必须在运行时落实的约束

1. **整数。** 大整数以十进制字符串编码，禁止正号、前导零、指数和浮点近似。正则限制最多 20 位仍不能确保 u64 上界，运行时继续检查 `0 <= n <= 18446744073709551615`。行数、catalog epoch、offset 和源 ID 同样遵守明确类型。
2. **独立状态。** `operation_status` 是唯一请求状态字段。`ok` 不等于 scope 完整。`execution.complete` 表示计算已经完成，不取决于响应是否已全部取走。spool 已算完而剩余传输被取消时，cancelled 与 execution.complete=true 可以同时成立；不把已完成事实强行降级。错误、取消和缺失流终态均不能当成完整审计成功。
3. **完整消费。** `emitted_rows` 在一次分页响应中为该页行数，在 stream 的 End 中为总交付行数；`total_rows_exact` 表示计数是否精确。需要外层操作 schema 与批次序列验证它们，不能仅通过本 envelope 推断完整性。
4. **分页。** `more_available=true` 必须带可续读的 cursor；`false` 对应 null cursor。原生 cursor 绑定 query 的固定 catalog generation 与快照，后续目录修改不混入旧查询。兼容 OFFSET 重执行单独命名。过期、关闭、worker 丢失不允许悄悄重开并拼页。
5. **覆盖。** scope 必须有可追溯 manifest；required_layers 由实际工作需求决定，不能为通过验收删掉必要层。`issues` 中阻断项必须反映到对应 coverage。`input/facts=complete` 需有事实和检查支持，单靠客户端填写该字符串不构成证明。
6. **错误。** `error` 成员与状态一致。`retryable` 是同一策略下可尝试恢复的提示，**不是自动换引擎的许可**。跨引擎 fallback 继续遵守 HostLab 迁移规范；语法错误不能包装成 unsupported 来绕过。
7. **文本和类型。** envelope 的 data 留给 operation/row schema。具体列通过 ordinal、稳定列 ID 与类型识别，允许重复 display_name。DEX MUTF-8、孤立 UTF-16 代理项、NULL、空值、bytes、非有限浮点必须按版本化值 codec 表达，不能有损替换后 hash 或比较。
8. **Profile。** admitted=true 需要真实的 conformance manifest 摘要；schema 只能检查摘要格式，不能验证它存在或覆盖了声明。能力 available、格式支持与整个 profile 准入分别维护。运行时还要验证 profile/dialect 名称、capability/transport 的 name+version、provider ID 及格式版本键唯一，并核查引用一致；JSON uniqueItems 不能保证这种语义唯一。
9. **通道。** capabilities 中 `mcp` / `mcp-stdio` 的 result_encodings 仅为 `["json"]`。worker/SDK 可单独声明 `json` 或列批；不能在 MCP stdout 插入二进制。
10. **观测。** benchmark schema 只接受 observed_run，不接受 projected。engine、输入、harness、机器与 artifacts 的 SHA 必须可验证；数字和证书均须来自真实运行。模型预测另存 model/projection 工件，不写成 B0/B1 已跑的记录。

## 有效预算的表示

`effective_limits` 是名称到预算对象的映射。对象包含 `value`（decimal-u64 或 null）、`unit`、`scope` 和 `enforcement`。`hard/soft` 必须有具体数值；`unavailable/unbounded` 必须是 null。0 是具体零额度，不代表无限。全局、worker、session、query 取适用的更严格额度；能力响应中的值只描述该响应对应上下文，不覆盖其他请求自己的更低限额。

最少应说明：`max_input_bytes`、`max_archive_members`、`max_member_uncompressed_bytes`、`max_total_uncompressed_bytes`、`max_fact_rows`、`max_build_memory_bytes`、`max_resident_facts_bytes`、`max_query_workspace_bytes`、`max_result_bytes`、`max_buffered_bytes`、`max_cursors`、`max_spool_bytes`、`max_threads`、`deadline_ms`。未落实的内核硬限制声明 unavailable，不用一个很大数字假装执行过。

## 基准记录与统计

每条 benchmark-run 是一轮单个 variant 的原始观测；`pair_id` 将同 workload、输入、机器、资源和缓存策略的两次运行配成一对，`block_id` 标识独立测量时间块。逐轮记录不能只保留最好成绩。

wall_seconds 是规定窗口的墙钟；metrics 中每个指标保留单位、范围和取得方式。未取得的指标写 null 及原因，不能写 0。byte/count 指标限定为 JSON 安全整数；超过 2^53-1 时必须升级为明确的十进制字符串指标契约，不能舍入。时间与比例可用有限浮点数；timestamp_utc 在运行时验证为 UTC。CPU 秒、采样 RSS、cgroup memory、真实峰值、映射虚拟大小分别命名；并发重叠阶段不当作串行成本相加。

comparison_mode 选择 ordered、bag、structured 或 expected_failure。没有 ORDER BY 仍保留多重性，不任意按 set 去重。equivalent=true 需要证书和零 mismatch；这还不自动代表性能资格。速度样本入选还要求 completed、complete_output、fallback_count=0、无污染、input/facts 完整、有效 canonical hash 和证书、ordered/bag/structured 比较，并核查配对输入、环境和窗口。W12 的预期失败可按 expected_failure 验证，不将其错误返回当作吞吐成绩。

## 交付包与未来 CI

`python3 tools/verify_kit.py` 校验原始交付快照；如安装了 jsonschema，还校验三个 schema 与形状示例。缺少 validator 时明确报告该部分未运行，不静默宣称完成。

开发时应在锁定的验证环境运行等价校验，并增加 operation schema、wire 状态机、C ABI ownership、真实 producer/consumer 和独立事实验证。当前 schema 无法替代这些测试；不得以通过 schema 为理由跳过完整性与差分 gate。
