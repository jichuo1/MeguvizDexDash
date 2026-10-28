# MeguvizDexDash 当前状态

更新日期：2026-10-28，Asia/Shanghai。任务状态以 tasks/backlog.json 为唯一任务图。

## 已交付什么

独立工程位于 D:\MeguvisDexDash，目录保留原拼写、产品名使用 MeguvizDexDash。私有远端 https://github.com/jichuo1/MeguvizDexDash 已建立，原始规格提交 3bbf1088137e70c5d3d722534a5eeab8b69a596c 已推送；M0/M1检查点43ad210与CI修复d9ce060已推送；M2元数据正准备阶段提交。

MDD-001/002/003/004/006 已按对应任务验收完成：来源冻结、Windows Rust 1.99.0/依赖实际构建、16 查询族/38 精确模板/56 关系/17 必需关系与三层工具、29 小语料及独立 oracle、有限 SQLite 虚表实验与结果契约决策。它们不授予产品 profile 资格。

原包严格校验通过：56 文件摘要、23 历史证据、51 无环任务、3 schema、4 正例、8 反例、2 取消状态。历史条件预算重算一致；约 37%/47% 仍是条件目标。

## 引擎实现状态

**in_progress。** MDD-010/011 已有真实 CLI 版本/能力入口、结果 Rust 类型、自有字节捕获和来源身份；JSON/schema、u64边界、同大小同mtime改写/重命名/删除/路径替换、重复来源、lease存活、摘要与零预算失败均实际测试。仅声明对应任务范围，未声明 DEX 完整解析或审计替代。

MDD-012/013/014 已完成成员清点/受限头校验/生命周期骨架验收。整仓32项测试通过后，生命周期又补充未消费cursor释放不能洗白成功的反例，当前session为8项测试；五种实际worker故障模式通过。M1全部五项任务已按限定范围验收；MDD-020字符串/类型/原型事实也已完成，17项DEX与3项facts测试及公开NewPipe完整元数据构建通过。主代理单写共享 Cargo/lock、types、snapshot、CLI、STATE/backlog/ledger/index 和 CI。没有性能独占测量或正式 benchmark trial。

## 已固定的研究锚点

- 目标：HostLab 的 DexSQL 桌面/云端职能；不替代 DexKit。
- 产品名：MeguvizDexDash；拟定命令与 backend：meguvizdexdash。
- 参考 HostLab：8782f43d537c442905123e35af325c412caa5188。
- 两个历史 A0 任务：94.630143 / 85.572220 秒，各一次观测。
- 约 37% / 47% 的完整任务降时为阶段条件目标，未有 B 实测。
- 实际环境：Rust/Cargo 1.99.0、Windows x86_64 MSVC、捆绑 SQLite 3.53.2；七项生产依赖已获用户批准，Cargo.lock 与 requirements-dev.lock 已固定。
- 固定研究提交的13份公开源码已逐文件取得并核验；现有干净 HostLab 工作树实际 HEAD=f0e523738cd0bb5575ff04b96e407dd62bdaface，未作修改。Windows DexSQL 0.1.0 和历史 Linux 两版身份分别登记。

## 下一动作

继续MDD-021定义/关系与MDD-023指令/代码布局任务；各模块限定写入权，主代理负责共享exports和最终集成。恢复先检查实际 Git/进程状态及任务图，运行 python tools/check_progress.py，按证据恢复，不重复创建任务图。

## 已知待验证项

MDD-005 受阻：已知两个私有样本目录只有 prepare.lock，没有9170100/9161100 APK；NewPipe公开样本现已从官方取得并核验10885562字节/SHA e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58，保存在被忽略的artifacts/local/inputs，不进入Git。A0/A1/A2 同环境完整驱动、结果证书与独占测量未建立，不选取虚构分母。

最终 SQLite 实验21项中16项匹配，5项是 NUL length、LIKE下划线、UTF16排序、孤立代理TEXT和TEMP CTAS差异。全部保留真实输出；MDD-031仍需无损文本/方言/目录适配，所有profile admitted=false。

M0/M1检查点d9ce060的Linux/Windows原生CI均通过，下载产物的10份命令记录全部exit0，见artifacts/integration/20261028/ci-d9ce060.json。M2新元数据仍需同版本CI；平台正式发行资格尚未取得。WSL未安装、没有Docker。DEX SHA-1现已另行批准sha1 0.11.0并按header-v2实际验证；完整ART验证、完整事实/资源、MCP/FFI/桌面与正式发行资格均未取得。BIL既有修改和全部外部工作树保持原状。

## 续写规则

原包副本 handoff/original/MeguvizDexDash 保持不变；CI可从初始Git blobs重建原始字节。开发命令和原始结果在artifacts，历史evidence仍保持历史含义。

本机命令隔离helper曾连续无法启动，后续已授权的本地命令经受审查执行方式恢复；Git每次限定 -c safe.directory=D:/MeguvisDexDash，没有改全局信任配置。

当前未修改HostLab生产配置、默认backend或共享部署。回滚采用新revert提交撤回候选实现，保留原规格和失败证据，不重置/清理其他工作树。远端仅为用户授权的新私有项目仓库。

MDD-020实际公开输入：classes.dex 64754 strings/9630 types/13644 protos；classes2.dex 3722/1034/1455，全部所选元数据计算完成。definitions/annotations/code/references/resources仍未建立，不将此摘要当完整审计。

SHA-1升级后仍未取得完整DEX/审计资格。原有传递版本未升级，候选全量重解析已拒绝并保留证据；见ADR-012。MDD-021/023正在实际实现，MDD-022先准备独立注解语料。
