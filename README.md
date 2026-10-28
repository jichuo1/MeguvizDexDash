# MeguvizDexDash 工程执行包

MeguvizDexDash 是面向桌面与云端、可嵌入且可服务化的 DEX 静态分析引擎。首个业务接入点是 `jichuo1/innocent-lab-host-analysis` 中 DexSQL 承担的职能。Android 进程内 DexKit 替换属于独立的 DexMeguviz 项目。

本包包含可交给编码 AI 的执行提示词、完整工程计划、接口契约、任务依赖、迁移与验证方案，以及此前真实研究的证据快照。**它是已经检查的工程规格与交接材料，不是已经实现的新引擎，也不包含可以投入生产的 MeguvizDexDash 可执行文件。**

## 开始使用

1. 将本包解压到编码 AI 可读取的工作区，保留相对目录结构。
2. 将 [AI_EXECUTION_PROMPT.md](AI_EXECUTION_PROMPT.md) 的完整内容交给 AI，并让它读取同目录的 [ENGINEERING_PLAN.md](ENGINEERING_PLAN.md)。若只有聊天输入权限，可先粘贴提示词，再上传本包。
3. 让 AI 检查当前工作区与仓库权限，创建或定位独立的 `MeguvizDexDash` 工程，从 M0 开始实施。现有 HostLab 与 BIL 工程作为接入方，保持独立。
4. 工作区已有规范优先按正常指令层级处理；[AGENTS 模板](templates/AGENTS.template.md) 用于补充工程约定，不覆盖用户已有指令。
5. 每完成一个任务，记录实际代码、实际命令、实际结果和证据。未执行或受阻的任务保留明确状态。

## 阅读入口

| 文件 | 用途 |
| --- | --- |
| [AI_EXECUTION_PROMPT.md](AI_EXECUTION_PROMPT.md) | 可直接复制的主执行提示词 |
| [ENGINEERING_PLAN.md](ENGINEERING_PLAN.md) | 目标、决策、阶段依赖、交付标准和实施顺序 |
| [证据基线](docs/00_EVIDENCE_BASELINE.md) | 已知事实、实测收益、未解问题与来源 |
| [决策与依赖](docs/01_DECISIONS_AND_DEPENDENCIES.md) | Rust、SQL 兼容桥、传输、可选 provider、桌面与依赖选择 |
| [核心架构与契约](docs/02_ARCHITECTURE_AND_CONTRACTS.md) | 模块、实体、生命周期、语义、协议与缓存 |
| [HostLab 迁移](docs/03_HOSTLAB_MIGRATION.md) | 真实入口、SQL、工具分层、适配、回退与切换 |
| [验证与性能](docs/04_VALIDATION_AND_PERFORMANCE.md) | 格式语料、独立验证、完整性、性能与发布门槛 |
| [执行与交接](docs/05_EXECUTION_AND_HANDOFF.md) | 多代理分工、开发循环、CI、证据与恢复 |
| [任务图](tasks/backlog.json) | 有依赖的机器可读任务；交付时工程任务均为 todo |
| [契约索引](contracts/README.md) | 拟定 JSON Schema 与语义约束 |
| [证据索引](evidence/index.json) | 原始附件、逐轮测量、行为观察及其 SHA256 |
| [交付包验证记录](VALIDATION_REPORT.md) | 本次实际执行的材料校验及其严格边界 |

## 先验证本包

在本包根目录执行：

```bash
python3 tools/verify_kit.py
python3 tools/recompute_targets.py
```

第一个命令验证文件摘要、链接、任务图及规格材料的内部一致性；第二个命令从原始 HostLab JSON 重新计算条件目标。它们不启动引擎，不依赖 APK，也不证明新引擎功能或性能已经达标。

## 当前性能口径

历史 A0 是 DexSQL 0.1.0 与已优化 HostLab，两个完整任务为 94.630/85.572 秒。让结构与 surface 两个完整阶段各快两倍、其余不变，对应 59.536/54.216 秒，降时 37.09%/36.64%。这只是阶段工程目标，完整 B 尚未实测。

已有上游 0.1.1 在公开 APK 的真实 HostLab 全量查询管道中测得配对中位约 2.88 倍速度；消费端列批原型对同条宽表查询测得约 6.78 倍组件速度。两者不相乘、不外推完整 BIL，也不都归为自研收益。M0 必须保留 A0、A1、A2、B0、B1 五组身份并重建同环境基准。

## 版本与证据

本包规格版本为 `0.1-draft`，整理日期为 2026 年 10 月 26 日，用户时区 Asia/Shanghai。原始日志时间保持其来源时区。HostLab 固定研究提交为 `8782f43d537c442905123e35af325c412caa5188`，后续实施必须同时保存固定基线与当时实际 checkout 身份，不能把快照当作所有部署实例的现状。

新设计与已知事实分开标注。规范性新增接口由契约文件和架构文档约束；它们都是待实现契约。引用的闭源 DexSQL 行为只覆盖已经观察或文档说明的范围，不声称恢复完整内部源码。
