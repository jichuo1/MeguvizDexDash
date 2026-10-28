# MeguvizDexDash 证据基线与未知项

本文件区分固定源码事实、历史测量、本轮局部实验和待实现设计。机器可读来源、字节数和 SHA256 在 [evidence/index.json](../evidence/index.json)。证据只证明其明确范围，不能自动扩大到全部查询、平台或应用。

## 1 项目定位与固定身份

首个接入仓库为 [innocent-lab-host-analysis](https://github.com/jichuo1/innocent-lab-host-analysis)，研究 commit `8782f43d537c442905123e35af325c412caa5188`。BIL 的 Android 进程内 DexKit 替代由独立 DexMeguviz 承担。MeguvizDexDash 是本工程新名称，尚没有在本次任务中实现运行核心。

| 对象 | 已固定身份 | 解释 |
| --- | --- | --- |
| HostLab | `8782f43d537c442905123e35af325c412caa5188` | 查询、适配与报告的研究源码快照 |
| DexSQL 0.1.0 Linux x64 | `f9e795e1e33547fdda451f592fe54c85e99c2138575f599540f5a860c1cef00c` | 现有安装器固定的 A0 二进制 SHA256 |
| DexSQL 0.1.1 Linux x64 | `f35c57610fcee62864e68f12e51997621375c025447aa2f32a0be9eb2df464bc` | A1 升级对照，不能冒充 A0 |
| AOSP ART | `6484611fd45e69db9f33f98bfd6864014b030ecf` | loader/verifier/instructions/host 接口研究快照 |
| AOSP frameworks/base | `99b01a65cc4c104933788b3143285ab6bae65827` | 资源与二进制 XML 参照 |
| 官方发布仓库 | `LSPosed/dexsql-release@b867cfeb33da3d3dc32c74d6f05c741eb60586b2` | 文档、公开基准与发布物研究快照 |

实施时应另记实际 checkout 与实际二进制；旧快照不能代替最新部署清单。输入 APK 身份从原始 verification JSON 读取，不靠版本名猜测同一内容。

## 2 真实 HostLab 的基线

来源是 [Actions run 40067936875](https://github.com/jichuo1/innocent-lab-host-analysis/actions/runs/40067936875)。原始附件长度、SHA256 与 ZIP CRC 已核对，当前 22 个工具摘要与固定 main 一致；本包保留原始 [verification.json](../evidence/hostlab_verification.json) 和推导说明的结构化结果。

| 阶段 | 9170100 秒 | 9161100 秒 |
| --- | ---: | ---: |
| 显式 prepare P | 1.442956 | 1.308335 |
| structural S | 13.663421 | 11.911596 |
| surface F | 56.525247 | 50.801524 |
| native 未分项 R | 0.253425 | 0.241183 |
| native 外 O | 22.745093 | 21.309582 |
| 完整 worker E | 94.630143 | 85.572220 |

这是每样本一个当前实现记录，4 CPU Linux runner、原生线程数 2，新建进程、已有 APK、OS cache 保留。它排除最初下载、排队和部分云流程，不能计算稳定 p95，也不是单条 dexq 延迟。

S/F 包含 DexSQL、输出、Python、指纹等多种成本，O 也包含输入、门禁、校验和报告。不能把 N 视为纯 engine，不能把 O 全视为可删除 Python。P 仅首次显式窗口，不是所有后续解析／索引工作的总和。

当前已实现的 64 KiB reader、有界队列、方法范围过滤、批内复用、物理 DEX 核对、源摘要检查和分组调度都属于基线。历史降时约 12% 的相关改动不能再次登记为自研新增收益。

## 3 最新量化结论及明确废弃项

根据真实阶段计算，其他不变时：S/F 各 2× → 59.535809/54.215659 秒；S 2×、F 3× → 50.114934/45.748739 秒。这些约 37%/47% 只是工程目标，完整自研 B 没有测量。

**废弃上一版蓝图中人为指定 15%/30% 等阶段权重及由此产生的 8.25%/32.25%/51.25% 示意模型。**不得将其带入本计划；使用 [measured_phase_model.json](../evidence/measured_phase_model.json)和原始阶段。假想整体内存和增量命中率模型同样不作为项目预测。

原始数据可通过 `python3 tools/recompute_targets.py` 重算。模型不启动引擎，不能用模型输出替代实际 benchmark trial。

## 4 本轮局部实测

公开 NewPipe 0.28.6 APK 为 10,885,562 字节、2 个 DEX，SHA256 `e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58`。同一五列 class_methods 查询全量 55,763 行，逐次完整有序结果摘要一致。

| 实验与计时范围 | 结果 | 可以支持的判断 |
| --- | --- | --- |
| 两版本 CLI hex 导出至 stdout 完整捕获 | 0.1.0 中位 4590.411 ms；0.1.1 中位 761.032 ms | 这个导出子任务的版本中位比约 6.03×；Python 最终解码不在计时内 |
| 原 HostLab 与真实进程管道至完整 dict | 5 轮配对倍速中位 2.8847×；各版本耗时中位 4034.933/1289.310 ms | 上游升级在该真实接口任务的改善；版本中位比 3.1295 与配对中位不是同一统计量 |
| 同一真实输出的消费端内存回放 | 846.784→124.889 ms | 约 6.78× 组件速度；排除 producer、DEX/SQL/索引和真实内核 pipe |
| 短字段 100k 行回放 | 284.628→181.968 ms | 约 1.56×，提示结果长度和表示方式强烈影响收益 |

实际有效 UTF8 内容 9.68 MB，紧凑 JSON 10.63 MB，列批原型 10.84 MB，普通表格 153.64 MB，hex 表格 305.38 MB。列批较原 hex 体积小 96.45%，但比紧凑 JSON 略大；该实验不证明 binary 一定优于 JSON，更不证明必须重写 DEX parser 才能改进。

完整来源分别见 [CLI 原始计时](../evidence/public_apk_profile.json)、[真实管道](../evidence/hostlab_public_pipeline.json)、[真实消费回放](../evidence/decoder_public_apk_results.json)、[短行回放](../evidence/decoder_microbenchmark_results.json)和[独立计时审阅](../evidence/public_apk_timing_review.json)。公开 APK、数百 MB 捕获和引擎二进制不放入本工程包；下载与复跑材料在上一轮[完整量化包](https://chatgpt.com/library?file_id=libfile_d18dfc1a95a88191bea32b92446d0944&account_id=personal)。

## 5 两版 DexSQL 行为研究

每版保留 manifest/checks/observations/CLI/MCP 原始记录，见 [0.1.0 观察](../evidence/compatibility/0.1.0/observations.json)与[0.1.1 观察](../evidence/compatibility/0.1.1/observations.json)。各 23 个脚本断言通过，断言含身份与控制条件，不等于 23 个独立功能或全部兼容性。

已观察到或有公开接口支持的重点：CLI schema 两版列出同一组 56 关系；0.1.1 支持 compact；缓存默认依赖原来源；同尺寸保留 mtime 的改写可导致缓存拒绝；驻留 SQL 与后续 decode 对源变化的处理存在差异；TEMP 变化能影响 offset 重执行分页；重复路径/内容不能简单视为一个逻辑输入；取消/超时可能关闭所涉 dataset。

这些用来制定差分和新 native 语义，不能推断闭源内部索引布局、具体缓存哈希算法或所有并发行为。`sqlite_dynamic` 等类型名也不能证明执行器内部就是 SQLite。完整公开行为的复刻程度通过 compatibility ledger 表达。

## 6 AOSP 参照的边界

- [DEX 格式规范](https://source.android.com/docs/core/runtime/dex-format)：格式版本、容器和 MUTF-8；041 在当前官方说明中仍为实验容器能力。实施时保留文档版本／获取时间并核对变化。
- 固定 ART loader、verifier、opcode 表和外部接口：完整边界、指令和验证参照。窄外部 C API 不能替代完整不可信输入验证。
- 固定 frameworks/base 资源实现：AXML/ARSC 参照，不意味着完整设备资源解析和 overlay 语义已被覆盖。

字符串必须保留 UTF16 code units；DEX 允许的孤立代理项不能直接有损替换为 Unicode replacement 字符。041 的逻辑 DEX 与物理容器及共享数据应分离。invoke-custom 需要显式处理，不能只用普通 invoke 标志建立调用事实。

如果产品 reader 与 oracle 复用同一段 AOSP 解析代码，独立性有限，需要不同实现与人工/变形语料补充。固定源码的文件和内容身份见两份 AOSP manifest；原代码从对应官方仓库固定 commit 取得。

## 7 M0 必须闭合或明确保留的未知项

| 未知项 | 实施动作 | 未完成时的结果 |
| --- | --- | --- |
| 实际部署 checkout、客户端与样本清单 | 冻结部署身份与输入摘要 | 不宣称覆盖所有实例 |
| BIL 完整 A1/A2 耗时与等价性 | 同机器同语料重新测量 | 自研相对最佳现成路径收益未知 |
| SQL 精确语义与动态查询形状 | corpus 录制与差分 | 相关 profile 不准入 |
| 输入、pure engine、输出、Python、gate 独立墙钟 | 真实链路分段 profile | 不按 CPU 秒或局部实验强行分配 |
| binary 与 JSON 完整链路成本 | 同数据、完整编码与消费对照 | 不预选性能优胜者 |
| Windows/macOS 原生行为与性能 | 对应机器和打包环境运行 | 不 advertise 未验证平台 |
| AOSP provider 与自有 reader 的共享实现 | oracle provenance 图 | 不误报独立双重验证 |
| 041、特殊容器、完整资源能力 | 独立 capability 与语料 | 明确 unsupported/experimental |

这些未知项通过任务图管理，不能以“继续研究”为由阻止无依赖工作，也不能因局部 demo 成功而悄悄删除。
