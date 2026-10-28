# MeguvizDexDash 当前状态

更新日期：2026-10-28，Asia/Shanghai。任务状态以 tasks/backlog.json 为唯一任务图。

## 已交付什么

独立工程位于 D:\MeguvisDexDash，目录保留原拼写、产品名使用 MeguvizDexDash。私有远端 https://github.com/jichuo1/MeguvizDexDash 已建立，原始规格提交 3bbf1088137e70c5d3d722534a5eeab8b69a596c 已推送；本轮实现正在工作树中，阶段提交待集成。

MDD-001/002/003/004/006 已按对应任务验收完成：来源冻结、Windows Rust 1.99.0/依赖实际构建、16 查询族/38 精确模板/56 关系/17 必需关系与三层工具、29 小语料及独立 oracle、有限 SQLite 虚表实验与结果契约决策。它们不授予产品 profile 资格。

原包严格校验通过：56 文件摘要、23 历史证据、51 无环任务、3 schema、4 正例、8 反例、2 取消状态。历史条件预算重算一致；约 37%/47% 仍是条件目标。

## 引擎实现状态

**in_progress。** MDD-010/011 已有真实 CLI 版本/能力入口、结果 Rust 类型、自有字节捕获和来源身份；JSON/schema、u64边界、同大小同mtime改写/重命名/删除/路径替换、重复来源、lease存活、摘要与零预算失败均实际测试。仅声明对应任务范围，未声明 DEX 完整解析或审计替代。

MDD-012/013/014 已完成成员清点/受限头校验/生命周期骨架验收。整仓32项测试通过后，生命周期又补充未消费cursor释放不能洗白成功的反例，当前session为8项测试；五种实际worker故障模式通过。M1全部五项任务已按限定范围验收，MDD-020继续推进。主代理单写共享 Cargo/lock、types、snapshot、CLI、STATE/backlog/ledger/index 和 CI。没有性能独占测量或正式 benchmark trial。

## 已固定的研究锚点

- 目标：HostLab 的 DexSQL 桌面/云端职能；不替代 DexKit。
- 产品名：MeguvizDexDash；拟定命令与 backend：meguvizdexdash。
- 参考 HostLab：8782f43d537c442905123e35af325c412caa5188。
- 两个历史 A0 任务：94.630143 / 85.572220 秒，各一次观测。
- 约 37% / 47% 的完整任务降时为阶段条件目标，未有 B 实测。
- 实际环境：Rust/Cargo 1.99.0、Windows x86_64 MSVC、捆绑 SQLite 3.53.2；六项生产依赖已获用户批准，Cargo.lock 与 requirements-dev.lock 已固定。
- 固定研究提交的13份公开源码已逐文件取得并核验；现有干净 HostLab 工作树实际 HEAD=f0e523738cd0bb5575ff04b96e407dd62bdaface，未作修改。Windows DexSQL 0.1.0 和历史 Linux 两版身份分别登记。

## 下一动作

继续 MDD-020 字符串/类型/原型事实，执行 Windows 定向复核并收集 Linux/Windows 原生 CI。恢复先检查实际 Git/进程状态及任务图，运行 python tools/check_progress.py，按证据恢复，不重复创建任务图。

## 已知待验证项

MDD-005 受阻：已知两个私有样本目录只有 prepare.lock，没有9170100/9161100 APK；NewPipe公开样本尚未取得。A0/A1/A2 同环境完整驱动、结果证书与独占测量未建立，不选取虚构分母。

最终 SQLite 实验21项中16项匹配，5项是 NUL length、LIKE下划线、UTF16排序、孤立代理TEXT和TEMP CTAS差异。全部保留真实输出；MDD-031仍需无损文本/方言/目录适配，所有profile admitted=false。

Linux原生CI尚待实际运行；WSL未安装、没有Docker，不能声明Linux已支持。DEX SHA-1、完整ART验证、完整事实/资源、MCP/FFI/桌面与正式发行资格均未取得。BIL既有修改和全部外部工作树保持原状。

## 续写规则

原包副本 handoff/original/MeguvizDexDash 保持不变；CI可从初始Git blobs重建原始字节。开发命令和原始结果在artifacts，历史evidence仍保持历史含义。

本机命令隔离helper曾连续无法启动，后续已授权的本地命令经受审查执行方式恢复；Git每次限定 -c safe.directory=D:/MeguvisDexDash，没有改全局信任配置。

当前未修改HostLab生产配置、默认backend或共享部署。回滚采用新revert提交撤回候选实现，保留原规格和失败证据，不重置/清理其他工作树。远端仅为用户授权的新私有项目仓库。
