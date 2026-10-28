# MeguvizDexDash 工程协作约定

遵守用户全局协议，始终中文沟通、先读后改、复杂工作先按依赖分析，修改前说明改什么和为什么。提交使用 `feat/fix/refactor/test/docs/chore/perf(scope): 描述`。

## 范围与权威文件

产品名为 MeguvizDexDash，命令 `meguvizdexdash`，crate 前缀 `mdd-`。工作区目录保留 `D:\MeguvisDexDash` 的现有拼写。通用核心不包含 BIL 包名、FEATURE、family、业务 protocol、版本选择或 GitHub Actions 规则；它们只进入集成层。DexMeguviz 与 DexKit 是独立项目，默认构建不依赖其源码或交付。

恢复先读 STATE、实际 Git 状态、tasks/backlog.json、相关 ADR/契约和当前原始证据。任务图只有 backlog，状态仅 todo/in_progress/blocked/done；任何反例推翻完成条件必须重新打开任务。不能为解锁后继任务、发布或性能资格缩小原验收。

## 改动与所有权

保留已有修改；不 reset/clean/全局 stash，不使用 git add -A。每组变更按明确文件清单提交。共享 Cargo/lock、schema、STATE/backlog/ledger/index 与模块 exports 由主代理单写，模块实现和独立验证按分工进行。新生产依赖先获得用户确认，并锁定实际构建过的版本；增量解析锁文件，避免无关传递升级。

不提交凭据、真实 .env、私有 APK 或本机运行环境。公开实物样本置于被忽略的 artifacts/local；合成小型 APK 可作为明确标注的 fixture。外部路径先核验绝对位置与转义。删除文件、分支重置、强推、生产部署和默认切换遵守用户当次实际授权。

## 正确性

捕获字节、查询、Smali、资源和指纹必须使用同一快照。物理内容去重不消除来源出现次数；引用/定义、物理成员/逻辑DEX、UTF16/MUTF8、NULL/空值、站点/去重边分开。变量长度项要由物理 map 遍历证明真实起点，落在 section 内不足以证明有效引用；合法未引用项和共享空项不能误拒。

partial/unknown、超时、截断、未消费页、取消、worker丢失或缺终态不能变成空成功。真实错误不得包装 unsupported；必需工作不能依赖整程 fallback 签替代资格。已实现但未验收的能力不自动 admitted。

## 验证与交接

原始工程包通过 `tools/verify_original_handoff.py` 从不可变初始 Git blobs 验证；该通过不是引擎测试。按改动风险执行实际测试、独立 oracle、边界和必要平台检查，未执行写明 not_run/blocked；不空实现、固定输出、吞异常、默认 skip 或只改 golden 制造通过。必要 Python 验收不依赖可被 -O 删除的 assert。

历史 evidence 保持历史含义，当前原始运行记录追加保存；artifact index、compatibility ledger 和 STATE 同步。重要经验保存现象、证据、根因、最终方案、失败方案、验证范围。构建、功能差分、静态分析、性能、设备/UI证据分别声明。

性能正式比较独占测量时段，保留 A0/A1/A2/B0/B1、同工作量完整消费和结果证书。历史约37%/47%仅条件目标，不叠加重叠收益或微基准。MDD-055/073可输出明确功能预览，正式性能发行仍需MDD-082，远端仓库进度存储不等于生产发布授权。
