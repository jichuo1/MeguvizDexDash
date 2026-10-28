# 基准与完整消费

当前没有本机 A0/A1/A2/B0/B1 的合格测量，不能从历史观测计算新引擎成绩。`baseline-manifest.json` 是预注册计划；`measurement-schema.json` 引用统一的实际单轮契约。

实际可用命令（工作目录为工程根）：

```powershell
& 'C:\Users\Administrator\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' benchmarks/run-existing-baselines.py --self-test
& 'C:\Users\Administrator\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' benchmarks/run-existing-baselines.py --preflight --output artifacts/mdd-005/preflight.json
```

前一命令仅测试严格 JSON、完整结果消费和 canonical 规则。后一命令核验实际文件摘要、输入多重性、固定driver、兼容证书及平台；缺项退出 2，未发起引擎。当前 Windows 无已验证的进程树 supervisor，WSL 子系统也未安装，正式基准因此保持受阻。脚本里的 POSIX 有界执行原语尚未在 Linux 实际运行，不能宣称平台通过。

当前脚本不是 DexSQL adapter，也没有可发起完整配对测量的已验收调度入口。它提供实际实现的 preflight、严格消费者、保留 stdout/stderr 的 POSIX 期限/输出预算原语；依赖闭合后继续接入真实 workload driver、独占时段 lease、逐轮 schema 校验和 paired coordinator，不能用任意命令输出代替审计结果。

未来 driver 用参数数组执行，禁止 shell 字符串；其单个 `mdd.benchmark-output.v1` JSON 包含 `input_manifest`、稳定 `request_key`、`row_schema`、`comparison_mode`、`final_dto`、`fallback_count`、最终 `mdd.result.v1`。只有 input/facts complete、计算完成、全部交付、无截断/剩余cursor、零fallback及完全物化才可进入结果比较。输入manifest保留有序 occurrence，业务DTO与原始代码/资源指纹均不得删除。

`mdd-canonical-json-v1` 使用 UTF-8 严格 JSON、对象键按 Unicode 标量排序、无空白、数组保持次序。NULL、bool、整数、文本类型分明；拒绝浮点隐式编码、孤立代理和超 i64/u64 整数。原始位型、bytes和DEX文本必须先由稳定DTO标签编码。bag模式仅排序完整 typed row，重复行保留；ordered模式不排序。该保守codec是基准工具范围，不代替引擎未来的值codec。

正式性能区间使用同输入/规则/最终DTO/缓存/总线程预算的交替配对，至少10对并在第二独立时间块复测；失败、超时、污染均保留。版本中位比与配对中位比分开，不由少样本生成p95。E/P/S/F/R/O保持实际时间窗，不把重叠 producer/consumer相加。历史37%/47%仅是A0条件目标。

补齐平台、引擎、私有输入和真实driver后先完成完整等价，再测量最佳合格A0/A1/A2；A2排除必须保留具体语义/部署证据。功能预览不等于 MDD-082 正式性能资格。
