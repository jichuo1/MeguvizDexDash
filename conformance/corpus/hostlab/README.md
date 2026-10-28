# HostLab 固定契约 corpus

固定提交：`8782f43d537c442905123e35af325c412caa5188`。

`source-8782f43/manifest.json` 保存每个已取得公开源文件的 URL、字节数和 SHA256；这是固定提交原始文件副本，不冒充本地完整 checkout。可按该 URL 重新获取并验摘要。额外探查的 `dexq/index.py` 返回 404，已保留为 unavailable；实际 legacy schema 位于已经取得的 `dexq/server.py`。

`queries.jsonl` 冻结 16 个查询族、真实生成表达式与来源行号。representative_sql 的参数是明确标注的合成示例，仅用于语义实验；source_expressions 保留业务生成器原貌。relation_schemas 是源关系完整 schema，不能当作实际查询返回列。result_schema_observed 和 golden 当前均为 null，execution_status=not_run。不得据此宣称全查询兼容。

`conformance/manifests/relations.json` 来自本机实际校验过的 DexSQL 0.1.0 Windows `tables` 响应，完整保存 56 个关系、列顺序、类型和可空性，其中 17 个为 HostLab 必需。cf.* / cm.* 完整列均保留。0.1.1 本机尚未重取 schema。

`tools-and-options.json` 的两版原生 12 工具完整 inputSchema 直接来自原工程包原始 tools/list；legacy 8 和 remote 12 从固定源码装饰器、签名、文档及行号提取。历史 tools/list 不是新引擎能力宣告。

复验命令（在工程根目录，Python 3.11+；不需要第三方包）：

```text
python conformance/corpus/hostlab/freeze_corpus.py
```

脚本只读指定来源、原始证据和已捕获 schema；重算限定 manifest/corpus，不打开 APK、不运行性能基准，也不修改外部仓库。产物验证在 artifacts/mdd-001/provenance-verification.json、artifacts/mdd-003/freeze-run.json 和 static-validation.json。

后续生产/兼容资格阻塞（不作为MDD-003静态冻结新增门槛）：缺少两个完整授权 HostLab APK、NewPipe 公开样本和当前完整消费 query golden；Linux A0/A1 尚未取得。两私有样本已知 hash 目录仅有 prepare.lock，不能算 APK 已取得。恢复后必须逐条录制返回字段/类型、NULL、顺序、重复次数、完整行摘要、覆盖、错误和引擎/输入身份，不能根据 source schema 填造 golden。

未改外部 worktree、未派发远端任务、未发布、未切换默认 backend。回滚本轮仅需停止引用本目录产物并保留证据，不执行清理或重置其他工程。

逐条验收：artifacts/mdd-001/acceptance-review.json 与 artifacts/mdd-003/acceptance-review.json。主代理复核后决定唯一任务图状态。
