# 工程交付包验证记录

日期：2026-10-26，Asia/Shanghai。对象是 MeguvizDexDash 初始工程提示词、计划、契约、任务和历史证据包。

**本记录不表示 MeguvizDexDash 引擎已经实现。没有构建、执行或测量新引擎，也没有修改 HostLab/BIL 业务代码。**

## 实际执行的材料校验

在写入文件后，实际运行了以下两种校验；JSON Schema 验证使用临时隔离位置中的 jsonschema 4.25.1，未加入未来引擎的运行依赖：

```bash
python3 tools/verify_kit.py --require-schema
python3 tools/recompute_targets.py
```

首项覆盖整个包的文件大小与 SHA256、严格 JSON 解析、23 份历史附件摘要、51 项初始 todo 任务及其无环依赖、Markdown 包内链接、初始未实现/未准入状态、3 份 Draft 2020-12 schema、4 份形状示例、8 个应拒绝样例，以及计算前/后的两种取消状态。校验成功。使用者未安装 jsonschema 时，普通校验会明确报告 schema 验证未运行；使用 --require-schema 则会失败，不能误报。

第二项从原始 hostlab_verification.json 重新选择当前 implementation=dexsql 记录，计算 P/S/F/R/O 和三组条件目标，并与既有 measured_phase_model.json 对照，结果一致。它没有运行 APK、没有执行 DexSQL，也没有产生新的性能观测。

## 复算结果

| 历史输入 | A0 秒 | S/F 各 1.5× 的条件秒数 | S/F 各 2× 的条件秒数 | S 2×、F 3× 的条件秒数 |
| --- | ---: | ---: | ---: | ---: |
| 9170100 | 94.630143 | 71.233920 | 59.535809 | 50.114934 |
| 9161100 | 85.572220 | 64.667846 | 54.215659 | 45.748739 |

每个历史输入只有一次 A0 观测。这不是稳定中位数、p95、B 的实测或跨机器承诺。条件保持其他成本不变、工作量/正确性相同且无新增开销；S/F 是复合阶段。

## 多代理审查及修订

架构、HostLab 迁移、格式/性能/交接分别由独立代理负责，并交叉检查主提示词、计划、schema 和任务依赖。修订了下列实质问题：

- 同一字段采用 operation_status、nullable sql_dialect、decimal-u64 catalog_epoch。
- 计算完成与结果交付完成分开；取消可以发生在已计算完的 spool 传输阶段。
- 原生 cursor 固定 query/catalog generation；目录变化不混合分页数据。
- 缓存描述表摘要进入 manifest，避免只校验 payload 而遗漏元数据绑定。
- HostLab 必需 decode/Manifest 在 M5 前完成，不推迟到扩展资源阶段。
- A2 经证据确认不可部署时允许排除；B0 固定 DTO/调度而非强制旧表格 wire。
- 门禁事实复用是按发行范围验收的能力，未采用则保留原独立门禁并计入 E。
- MDD-055/MDD-073 提供功能预览出口；正式性能发行仍要求 MDD-082 资格。

审查是工程规格的一致性检查，不是实现的形式证明或生产 conformance。真正代码、格式、故障、平台、性能和完整业务资格按任务计划实施后另行记录。

## 包完整性与后续改动

PACKAGE_MANIFEST.json 列出除它自身外的交付文件摘要。原包验证适用于此次冻结交接；后续实现造成文件/任务状态变化是正常行为。代码 CI 使用阶段定义的验证，不以保持初始文档 hash 为开发目标。重新发行工程材料时生成新 manifest，保留原始历史证据与更正说明。
