# MeguvizDexDash：格式正确性、结果证书与性能验收规范

版本：工程设计 v1；证据截点：2026-10-26。本文面向桌面和云端可复用 DEX 分析引擎及 HostLab 适配，**不是 Android DexKit 替换计划**。

本文中的 MUST / 必须是拟定的项目验收要求；数值门槛是项目策略，需在 M0 冻结，后续修改必须留下决策记录。它们不是 AOSP、DexSQL 或数据库产品保证的性能指标。除明确列为“已有测量”的项目外，本文描述待实现、待验证的能力，不能把本规范本身当作测试通过证明。

实现顺序应服从工程计划。本文 G0–G6 是验收关卡，可映射到多个开发里程碑；它们不要求一次实现所有可选格式。默认执行路线是 **typed QueryIR 快速路径 + 经 M0 验证的只读 SQLite virtual-table 兼容桥**，不是把全部 DEX 预先导入 SQLite，也不是先重写一个完整 SQL 数据库。

## 1. 验收原则与结果状态

### 1.1 优先级

1. 输入身份、内存与范围安全成立。
2. 请求范围的事实、引用次数、顺序和原始字节语义成立。
3. 失败、未支持、取消、限额、部分覆盖能被调用者识别。
4. 通过完整结果等价检查后才比较时间与资源。
5. 性能结论按实际计时窗口归属，不把协议、上游升级或宿主改动的收益归给新 parser。

不能以少扫描一个 split、忽略坏方法、只返回首批数据、把多重关系改成集合、关闭校验或漏掉最终字典物化，换取“更快”的验收结果。

### 1.2 统一结果 envelope，保留四种不同含义

沿用公共契约 `mdd.result.v1`，字段和枚举以公共 schema 为准；本文不定义另一套不兼容接口。

| 轴 | 字段 | 必须表达的含义 |
| --- | --- | --- |
| 请求终态 | `operation_status=ok/error/cancelled` | 请求是否完成协议处理；不代表业务结论成立 |
| 来源与事实覆盖 | `coverage.scope_id`、`coverage.input`、`coverage.facts`、`required_layers`、`issues` | 相对于声明范围是 `complete/partial/unknown`；哪些输入、方法或事实层未覆盖 |
| 执行完成度 | `execution.complete` | 查询计算是否完成；计算尚未完成的中断不得标 true，传输可在计算完成后另行失败 |
| 返回窗口 | `response.schema_id/emitted_rows/total_rows/total_rows_exact/more_available/truncated/next_cursor` | 是合法分页、明确截断，还是全部结果已消费 |

`snapshot_id`、`session_id`、`catalog_epoch`、`query_id` 必须能将这些字段与来源和计划绑定；`session_id` 是必需字段，可为字符串或 null，`catalog_epoch` 采用 decimal-u64 字符串。`profile` 与 `sql_dialect` 分开记录。合法分页的 `more_available=true` 不等于输入不完整；但仅消费第一页不能获得“完整结果等价证书”。`total_rows_exact=false` 时不得把估计行数当作证明。

完整成功证书的共同门禁为 `operation_status=ok`、`execution.complete=true`、请求范围的 input/facts coverage 均 complete、`truncated=false`、`more_available=false`、`next_cursor=null`。稳定 native cursor 必须绑定 snapshot/session/catalog/query；compatibility profile 的 offset 重执行不是同一种 cursor 保证。

`found / proven_absent / unknown` 是上层分析结论。核心 SQL 返回零行本身不是 `proven_absent`。确证不存在至少要求：相关输入集合已定义且完整、所需事实层完整、执行完成、范围与谓词一致，并且没有遗漏未消费的相关结果。完整倒排索引可以证明无命中，不要求机械全扫描；索引的完整性证据必须与快照一致。

### 1.3 严格分析、受限分析与兼容行为

- **严格请求**：所需来源或事实损坏、缺失、歧义时失败；不能自动生成完整业务报告。
- **明确允许部分结果的请求**：可以返回已验证事实，但必须带 issues 和实际覆盖范围；上层不得把它写成完整验收成功。
- **未支持能力**：与坏格式分开。无法识别某个版本、缺少插件或资源预算不足，不能统称文件损坏，也不能返回空数据表示没有实体。
- **兼容差异**：DexSQL 固定版本的可观察行为与格式规范是两种 oracle。已证实的旧行为如需保留，应由版本化 compatibility profile 表达；不得静默修正旧结果再宣布完全兼容。
- **回退**：只有明确的 `Unavailable` 或约定的 `Unsupported` 才能按用户/宿主选定的策略回退。输入变化、部分覆盖、损坏、歧义、取消和超时不触发隐式重试到另一引擎后报成功。回退也不能悄悄更改输入选择策略。

## 2. 能力矩阵：声明粒度必须小于“支持 DEX”

每条能力记录至少包括：能力 ID、格式/版本、平台、状态、解析策略、参考依据、fixture 集摘要、验证器版本和最后通过的 gate。状态采用 `planned / experimental / supported / unsupported`。任何 planned 项不得出现在面向用户的已支持清单中。

### 2.1 输入与格式范围

| 能力 | 首个生产目标 | 最低通过条件 | 不得扩大解释 |
| --- | --- | --- | --- |
| 普通小端 DEX `035` | 必需 | 表结构、编码值、指令事实和请求所需验证层全部通过 | 不自动覆盖早期 009/013 |
| 普通小端 DEX `037` | 必需 | 独立版本语料及版本约束通过 | 不能只修改 magic 字符串就声称支持 |
| 普通小端 DEX `038` | 必需 | call-site、method-handle、custom/polymorphic 等相关结构和指令通过 | 引用事实不等于运行时派发目标 |
| 普通小端 DEX `039` | 必需 | method-handle/type 常量及该版本实际结构语料通过 | 不自动支持所有 boot class path 专用扩展 |
| 普通小端 DEX `040` | 必需 | 名称与字符串等版本规则有正反例 | 不等同于 041 容器 |
| `036` | 默认 unsupported，专项调查 | 若要支持，先找到真实语料、格式依据和独立验证路径 | 旧 HostLab 原始指纹 allowlist 出现 036，不证明 parser 支持；也不能因此静默改变遗留结果 |
| `041` 多逻辑 DEX 物理容器 | 单独 experimental，非首版默认 | 第 4 节全部通过；能力开关、来源模型和共享依赖验证独立发布 | 不宣称所有 Android 版本可运行或已生产兼容 |
| 反向字节序、未知 magic/version | 默认 unsupported | 显式能力检测和结构化错误 | 不按本机字节序猜测，不当作空 DEX |
| APK/ZIP stored、deflate | 必需 | 完整成员清单、边界、解压、CRC 和内容摘要验证 | stored 可映射不代表免校验 |
| 单磁盘 ZIP64 | 必需输入能力，允许配置大小预算 | 64 位长度/偏移/计数、extra fields 与 descriptor 测试 | 格式支持不等于可以无上限分配内存 |
| 多 DEX APK | 必需 | 按显式成员选择 profile 盘点全部候选，保留每个 occurrence | 不能在 classes 序号有缺口时静默提前终止 |
| base + split APK 集合 | 独立能力 | 明确有序来源集合、缺失/重复 split 与类冲突规则 | 一个 base 文件不等于安装集合完整 |
| AXML 原始指纹 | HostLab profile 必需 | 精确原始字节范围与现有算法等价 | 不意味着完成 XML 语义解析 |
| AXML/ARSC 结构解析 | 可选资源插件；依实际 HostLab 查询 profile 决定是否阻塞 HL-MVP | 第 6 节通过 | 不自动支持 overlays、protobuf 资源或设备运行时选值 |
| CompactDex | 按具体版本的可选插件 | 独立数据区、共享区与恢复语料通过 | 不能从 AOSP 源码仍有类名推导当前统一 loader 支持 |
| VDEX / OAT / quickened 输入 | 按具体版本的可选插件 | 输入来源、伴随文件、环境依赖和恢复完整性明确 | 不能泛称“全部 ART 产物” |
| 加密 ZIP、分卷 ZIP、未知压缩方式 | 首版 unsupported | 能识别并清晰拒绝；不漏报被跳过的候选 DEX | 不能把无法读取的成员算成不存在 |

固定 AOSP `standard_dex_file.cc` 的接受集合是 035、037、038、039、040、041；这也是必须显式枚举、不能含混写“35–41 全支持”的原因。官方 DEX 文档在本次查阅时仍将 041 标为 Android 16 的实验容器格式，不建议用于生产代码。[S1][S2]

### 2.2 解析层与分析层分门

至少发布以下能力层，不用一个布尔值代替：

| 层 | 产物 | 完成判定 |
| --- | --- | --- |
| container inventory | 来源、成员、逻辑 DEX 清单 | 选择范围内候选都已盘点，未读项有原因 |
| checked structure | 头、表、类/字段/方法/原型、编码值 | 请求涉及的数据范围、索引和结构约束成立 |
| instruction facts | 全部已请求方法的指令及位置化引用 | 完整解码代码区，无未知 opcode 被跳过 |
| structured disassembly | AST、PC、标签、payload、try/catch、可选 debug | 可回溯原字节；展示格式版本明确 |
| CFG | 普通边、异常边、出口及不确定边 | 图模式、可达性和异常策略固定 |
| def-use / SSA | 定义使用、宽值、参数、phi 等 | 分析世界、算法版本、预算与 unknown 明确 |
| environment-dependent verification | 依赖 classpath 的更强验证 | classpath、解析策略和未解析项全部可追踪 |

基础字符串检索可以不构建全库 CFG；但必须如实记录没有构建的层。checked structure 通过不等于 ART 类型验证通过，更不等于 APK 已运行验证。

## 3. APK/ZIP 导入验收

以下均是项目测试义务。ZIP 记录、ZIP64 和 data descriptor 的格式依据为 PKWARE APPNOTE；项目拒绝或保留歧义成员的策略另行版本化，不能冒充 ZIP 规范的唯一行为。[S3]

### 3.1 成员身份、重复名称与路径

- `ContentId` 是物理 blob 的 SHA-256；`SourceOccurrence` 还要保留输入槽位、ZIP 成员序号/定位及逻辑 DEX 头位置。同内容重复出现可以共用存储，不能共用 occurrence 身份。
- 以 central-directory 成员枚举为清单依据，并验证其 local header、实际数据范围和所需 descriptor。不能只在文件中搜索 `dex\n` 或 `PK` 字节串建立可信清单。
- 重复成员名、大小写差异、不同 Unicode 编码、同偏移多引用都必须可观察。不得先放入 `name -> bytes` 字典再解析，从而丢掉前面的同名成员。
- 标准 Android 成员选择与“扫描归档中所有候选 DEX”是不同 profile。分别测试 `classes.dex`、`classes2.dex`、`classes10.dex`、缺号、非标准目录、同名不同内容和同内容多份；不以词典排序冒充数字顺序或加载顺序。
- 首选从受检 slice 读取，不按成员路径写盘。测试 `../`、绝对路径、Windows 盘符/UNC、反斜线、NUL、特殊目录和 symlink 属性；它们不能逃离工作目录或与正常成员被静默合并。
- 如某适配器必须落盘，落盘键应由内容和 occurrence 生成，而不是直接使用不可信成员名。文件系统对大小写、Unicode 和保留名称的差异不得改变分析来源集合。
- 对当前 HostLab profile 无法无歧义选择的重复 DEX 名称，报告歧义并阻止完整审计证书；不能偷偷采用 first-wins/last-wins。明确的取证 profile 可展示全部成员，但不能伪装为同一安装加载语义。

### 3.2 长度、偏移、CRC 与解压

必须覆盖下列正反例，并在结果中区分不支持、损坏与预算中断：

| 测试组 | 必须检查 |
| --- | --- |
| 基本记录 | EOCD/central directory/local header 的边界、记录长度、成员数、文件注释、合法空归档 |
| header 对照 | 名称/方法/标志/长度在允许规则下的一致性；不能把使用 descriptor 的零占位字段直接判坏 |
| data descriptor | bit 3、带/不带 signature、32/64 位尺寸；不能靠扫描数据内偶然出现的 signature 决定边界 |
| ZIP64 | sentinel 与 extra field 的对应关系、locator/EOCD64、64 位字段、超过 32 位的受控稀疏 fixture、截断与算术溢出 |
| 数据范围 | compressed slice、解压产物长度、首末字节；成员与元数据异常重叠按已冻结策略处置，合法签名块等区域不能被误当坏 ZIP |
| stored | 未对齐数据偏移、短文件、映射边界、页面边界；验证前不能随意形成越界指针 |
| deflate | 截断流、错误 stream 结束、长度不符、损坏 CRC、极端展开比、输出上限与取消 |
| 完整性 | 对消费的解压成员计算并核对 CRC；另保存强内容摘要。CRC、DEX header checksum 和 APK 签名不是同一个承诺 |
| 资源预算 | 总压缩/解压字节、成员数、单成员大小、时间、嵌套导入和临时磁盘上限；预算不足不是成功返回少量 DEX |

APK 签名真实性验证如成为产品能力，需要独立能力和 oracle；“读取到签名信息”或“CRC 正确”不能称签名已验证。导入普通静态分析不应默认执行 APK 或 ART 编译流程。

### 3.3 多输入快照与变化检测

输入 manifest 必须固定文件内容、选定成员、split 顺序/角色和选择策略。导入期间发生原地改写、截断、替换或来源集合变化，应失败或重新建立新 snapshot；不能把部分旧字节和部分新字节组成一份成功报告。

“只读映射”只约束本进程的写权限，不保证另一个进程不会改底层文件。内容寻址副本、不可变发布、lease 与校验策略应有各平台测试。Windows 映射偏移按 allocation granularity 处理；不能只把 Linux 的页对齐常量移植过去。[S10]

## 4. 标准 DEX 与 041 专项验证

### 4.1 普通 DEX 的最低测试矩阵

| 子系统 | 正确性要求 | 必须有的边界与失败 fixture |
| --- | --- | --- |
| header / map | magic、版本、endian、文件/头长度、section map、对齐和表大小关系按该版本验证 | 小于头部、0/最大计数、off+len / count×stride 溢出、越界、错误 map、非法重叠；不能一概拒绝格式允许的共享 |
| checksum / identity | 明确 strict、compatibility、forensic 策略；原始 SHA-256 与 DEX 自带完整性字段分别记录 | 错 checksum、错 signature、合法结构但声明不符；允许检查部分事实时也不能获得严格输入完整证书 |
| MUTF-8 | 保留原字节和可无损表示的 UTF-16 code units；长度是对应单位，不按 UTF-8 字节数代替 | 编码 NUL、空串、BMP、代理对、孤立代理、终止符缺失、非法 continuation、长度不符、截断 |
| ULEB/SLEB | 限定读入范围、位宽、终止和溢出；每次读入必须有进展 | 0、最大值、符号边界、超长、未终止、越界；非最短编码按冻结 profile 裁决，不凭感觉一概接受/拒绝 |
| string/type/proto | 表索引、描述符语法、数组维度、返回值/参数、shorty 和参数序列的一致性 | 越界索引、非法 void 位置、重名不同 proto、不同 DEX 的相同 local index、长 descriptor、版本名称规则 |
| field/method IDs | 分开引用与定义；保留 owner、name、type/proto 和来源 | 相同名字不同 descriptor、仅引用没有定义、重复声明与冲突、跨 DEX 同名 |
| class_data | delta 索引按各自列表作用域累加；边界与溢出受检；flags/code_off 的规则一致 | 大 delta、截断、重复/倒序、无代码方法、非法 code_off、列表间错误复用累加器 |
| encoded_value / annotations | tag/value_arg、嵌套结构、数组、注解、enum、method type/handle 等按版本校验 | 未知 tag、非法宽度、深度/元素预算、递归截断、越界 ID；预算失败不丢注解后报完整 |
| debug 信息 | offset、PC/line/register 推进及可选保留语义 | 缺失、截断、溢出和非法寄存器；不需要 debug 的请求不应被默认为已验证 debug |
| code_item | registers/ins/outs、insns_size、代码范围、padding、tries 与 handler 区 | 奇数 code-unit padding、边界代码、巨大长度、代码与 handler 截断、无进展遍历 |
| instruction | opcode/format/宽度、寄存器、宽值和所有引用索引 | 保留 opcode、版本不允许的 opcode、jumbo/range 边界、末尾不完整指令、越界寄存器 |
| payload | packed/sparse switch 与 array payload 单独解析；不是普通执行指令 | 对齐、元素宽度/数量乘法、key 顺序、负/正分支偏移、截断 payload、跳到 payload/指令中间 |
| try/catch | try 区间、顺序/允许的重叠规则、handler 偏移、类型列表、catch-all 与目标 | handler 不存在、无效地址、溢出、重复异常类型等规则反例；异常入口和 move-exception 约束分层处理 |

基础依据为 DEX 格式、字节码规范以及固定 verifier/opcode 源码；表中大量项目是本工程的测试设计，不表示已经执行通过。[S1][S2][S4][S5]

不得用标准 UTF-8 的“遇错替换为 U+FFFD”掩盖 MUTF-8 原值。面向 SQL、JSON、Arrow 或 Python 的展示转换必须声明可逆性；原始 MUTF-8 可作为 Binary 或有明确语义的扩展类型。显示字符串与原始指纹不是同一列。

### 4.2 动态调用、引用重数与 CFG

固定 AOSP opcode 表中 `INVOKE_CUSTOM`/range 使用 call-site 引用，但没有 `kInvoke` 标志；polymorphic 同时带 method 与 proto 引用。因此只判断 `IsInvoke()`/`kInvoke` 的统一扫描不是完整调用引用实现。[S5]

测试至少保留以下分开的关系：

- `instruction_method_ref`：指令编码中的 method ID。
- `instruction_proto_ref`：包括 polymorphic 调用点原型。
- `instruction_call_site_ref`：custom 调用点及其 bootstrap、名称、原型和静态参数。
- `method_handle_target_ref`：按 handle 类型分为字段或方法目标。
- `possible_dispatch_target`：由类层次、classpath 和分析策略导出的候选；带 unresolved/unknown，而不是必然真实调用边。

同一方法在两个 PC 引用同一目标，要保留两次 occurrence。值字典去重可以共享字符串存储，不可改变 `COUNT`、join、调用次数或证据位置。

CFG 必须分正常边与异常边；处理不可达代码、payload、循环、switch、返回、throw、try/catch 和保守未捕获出口。def-use 必须处理 64 位寄存器对、参数布局、move-result、move-exception 和合流。先对明确的小方法逐条裁决，再做大样本差分。若承诺可重新汇编的 Smali，另设 assemble→parse→语义等价 gate；漂亮的反汇编文本不是往返证明。

### 4.3 041 必须独立通过的门槛

041 是物理容器中的多个逻辑 DEX，而不是把几个传统 DEX 字节串连接起来。固定代码和官方规范使用物理容器地址基准、逻辑头位置以及后续共享数据。实现不应把每个 `file_size` slice 交给旧 parser 后宣布兼容。[S1][S6]

必须有以下专门 fixture 与属性：

1. 单、双、三个逻辑 DEX，逻辑头位置与 `header_offset` 相符；`container_size/file_size` 经溢出检查，遍历推进并正确终止。
2. 共享字符串与非共享同值字符串同时存在；每个逻辑 DEX 保留自己的 string ID 和 occurrence，不能合并成一行。
3. 索引、payload、字符串等偏移按各自规定的地址空间解释；禁止 `ContainerOffset`、`HeaderOffset`、`CodeUnitPc` 与宿主指针裸整数混用。
4. 合法前向共享、共享尾区边界、尾区截断、错报长度、指向头/非法区域、零进展/循环式遍历全部可判定。
5. `data_off/data_size` 不套用旧式连续数据区假设；不同格式混合、未知扩展有明确拒绝规则。
6. 任一共享依赖改变，相关缓存失效。物理容器内容摘要与 logical occurrence 一起进入来源身份；不能仅使用某个逻辑 header checksum。

固定 AOSP 中逻辑 `Size()` 与 `file_size` 相关，checksum 计算也依此范围；它不能替代覆盖全部前向共享数据的物理容器身份。[S6] 首版不具备这些语料时，正确行为是 `experimental/unsupported`，不是将该门槛推迟到解析上线之后。

## 5. AOSP 复用与 oracle 独立性

### 5.1 不把 stock libdexfile 当通用跨平台 SDK

AOSP 的 host target、Darwin/Windows 构建配置和内部 C++ 类存在，不等于已提供可直接发行的稳定桌面 SDK。固定构建仍有 libartbase、libbase、libziparchive、日志、压缩及生成头等依赖，必须固定依赖闭包并实测每个平台。[S7]

AOSP external `ADexFile` 确有明确的稳定 C ABI，但用途较窄，输入内存/回调寿命和线程限制需要遵守。固定 `ADexFile_create` 使用 `verify=false`、`verify_checksum=false` 打开数据，不能直接成为任意上传文件的完整验证边界。[S8]

若复用 AOSP，验收须额外记录：upstream commit、补丁、依赖版本、编译器、导出符号、校验开关、适用格式、对象/输入寿命和线程策略。公共 MeguvizDexDash ABI 不暴露 ART 内部 C++ 类型。不能要求桌面用户机器上存在未打包的 Android 私有库。

### 5.2 每条 oracle 必须有“共同实现祖先”记录

| 被测能力 | oracle 组合 | 独立性限制 |
| --- | --- | --- |
| ZIP 盘点/解压 | 规范向量 + 与主解析库不同实现的读者 + 手工清单 | 不同库对重复名称可能有不同选择；比较成员 occurrence 而不是只比 map |
| DEX 结构/指令 | 人工可推导的小 fixture + 固定 AOSP verifier/dexdump + 独立解析实现候选 | 核心若已用 libdexfile，AOSP dexdump 不是独立 parser oracle |
| Smali | 固定装配器生成 + 另一个解码器 + 源字节定位 | 同一个 parser 先读再写的自洽只算 round-trip，不算外部正确性 |
| AXML/ARSC | 手工 chunk 向量 + 固定 AAPT2 dump/解析 + 独立实现候选 | 主插件若直接用同一 androidfw，AAPT2 有共同依赖，需独立向量补强 |
| DexSQL SQL 兼容 | 固定 0.1.0/0.1.1 黑盒 + 完整结果 + 手工关系代数期望 | 闭源引擎是兼容 oracle，不是所有坏输入的标准裁决者 |
| QueryIR/索引 | 同一事实集上的简单全扫描参考执行器 | 必须避免参考执行器共用被测索引/谓词捷径 |
| HostLab | 固定工具源码、完整报告与原有 verifier + 扩展证书 | 原 verifier 未检查的语义不能以旧 hash 通过为由豁免 |

独立实现候选如 dexlib2/smali 或其他 ZIP/resource 解析器，必须在纳入前固定项目、commit、许可和实测版本范围；本文不预先承诺它们支持 041 或任意扩展。不能用“两个同源实现都接受”给错误输入背书。

差分出现不一致时，必须保存最小输入、原字节位置、双方状态和结果、规范/版本依据，由人工或可审查的 fixture 期望裁决；不得用多数票、改 golden 或忽略崩溃来消除失败。

## 6. 可选资源与运行时产物分支

### 6.1 AXML / ARSC

资源插件使用自己的字符串和结构规则；不能复用 DEX MUTF-8 解码器来解析资源 UTF-8/UTF-16 字符串池。固定 ResourceTypes 与 AAPT2 源码是已阅读的参考依据。[S9]

| 范围 | 必须覆盖 |
| --- | --- |
| chunk 框架 | type/headerSize/size、嵌套边界、对齐、未知 chunk 策略、零进展与溢出 |
| 字符串池 | UTF-8/UTF-16 两种编码及长度、offset、终止、style span、空值、共享与坏编码 |
| AXML | namespace、节点事件、attribute 原值/类型值、resource map、名称/前缀、引用来源 |
| ARSC | package/type/key/string 池、type spec/entry/config、稠密/稀疏或其他已声明布局、复杂 entry/map、包/类型/entry ID 范围 |
| 配置与引用 | 所有配置保留；未知配置字段可观察；未指定设备配置时不伪造唯一运行时值 |
| split/overlay | 输入世界、包 ID/动态引用及 overlay 策略单独 capability；不以数值 resource ID 跨 APK 自动 join |
| 原始指纹 | 直接来自相同原始字节与范围；解析后重新序列化的 XML/ARSC 不可替代 raw fingerprint |

仅原始资源指纹的 HostLab 请求不应强制为所有资源构建重型语义图。反之，只会 hash 原始文件不能宣传完整资源查询。AAPT2 protobuf 资源作为另一输入能力，未实现时明确未覆盖。

### 6.2 CompactDex / VDEX / OAT / quickening

每个插件必须拥有独立支持表：格式 magic/version、对应 AOSP commit、需要的伴随输入、外部 classpath/boot image 假设、可恢复事实和不能恢复的事实。

- CompactDex：明确共享 data 区与 code/debug 编码。固定当前 `OpenCommon` 的实际路径不能仅因源码中存在 `CompactDexFile` 类型而推断支持。[S11]
- VDEX：按具体 version/section 读取；checksum、DEX 内容和 verifier dependencies 各自保留。缺失 DEX 不制造空方法清单。
- OAT：编译产物与 class loader context、源 DEX、架构等环境有关；机器码反汇编与 DEX 事实是不同能力。
- quickened 指令：只有恢复信息足够才映射回标准语义；无法恢复的 operand 不得伪装成普通 method/field ID。

历史 dexlayout/CompactDex 的冷热布局、去重和紧凑偏移可以用于自有 sidecar 设计，但不能把 ART 编译/运行收益转换为静态查询性能承诺。常规 APK 分析也不应为此自动执行 dex2oat。[S11][S12]

## 7. 完整报告 canonical 证书

这里的“证书”是可复核的结果 manifest 和摘要，不是 APK 签名、代码签名或运行正确性的数学证明。签名发布时可以另签证书文件，但不能改变其语义边界。

### 7.1 必须包含的内容

| 组 | 证书内容 |
| --- | --- |
| 构建身份 | 引擎/适配器源码与二进制 SHA、依赖锁、ABI/fact schema/IR/storage/compatibility profile 版本 |
| 来源 | 完整 input manifest、ContentId、SourceOccurrence、成员/逻辑 DEX 定位、选择策略、split/解析世界 |
| 请求 | snapshot/catalog/query 身份、规范化请求/计划摘要、参数、规则 bundle、所需能力/事实层 |
| 覆盖 | input/facts coverage、执行完成度、所有 skipped/unsupported/invalid/unknown 项及原因 |
| 关系语义 | 每个 relation 的 schema、行数、NULL 数、排序契约、bag/set/sequence 模式、逐分区和总摘要 |
| 位置与重数 | 方法/字段/字符串/类型/call-site 等引用的来源实体、PC 和 occurrence；重复引用的 multiplicity |
| 原始证据 | 原始 APK/DEX/资源/代码字节指纹及算法、范围、单位、版本；不与语义规范化 hash 混用 |
| 业务报告 | FEATURE/规则结果、gate、类/方法事实、调用边、协议与资源指纹、跨版本变化等完整字段 |
| 输出消费 | 全部结果已消费或明确剩余；分页 token、截断/限额、失败状态；稳定的最终 commit 状态 |
| 测量链接 | 本证书对应的 trial ID；时间和资源文件独立，不纳入语义结果摘要 |

现有 HostLab 历史 verifier 比较 20 组证据字段，并比较跨版本的 changes/resource_changes/verdict；这作为迁移基线保留，而不是新证书的上限。历史 `audit_complete=true` 仍可能包含业务 `MISSING/PARTIAL`、`runtime_verified=false`，退出码也不一定是 0；验收需按原有明确规则解释，不能把它改写成“所有功能适配成功”。[H1][H2]

### 7.2 Canonical 编码规则

先固定 schema，再编码每个字段的类型、NULL 标志、显式长度和值。可以采用自有简单二进制规范或严格限定的现成 canonical 编码；M0 必须冻结格式并提供测试向量。

1. 区分 NULL、空字符串、字符串 `"NULL"`、整数 0、字符串 `"0"`、空字节串；不能依赖 repr、终端表格或不定长分隔符。
2. 整数使用固定符号/位宽规则；若支持浮点，明确 NaN、负零和文本转换规则。未实现的类型不能随意转字符串后获得同 schema 证书。
3. MUTF-8 原始值、无损 UTF-16 code units 与展示文本分开。不能 Unicode normalization、locale casefold 或替换坏字符后再称原值相同。
4. 位置 ID 保留 source occurrence、logical DEX、kind、local index。descriptor 是符号键，不是全局唯一实体 ID；`file_id` 的外部重编号必须有基于来源的明确映射。
5. `bag` 比较可以按完整 typed row 排序，但保留重复项及计数；不能转 set。合法 SQL `DISTINCT/UNION` 去重属于算子语义，需单独验证。
6. `sequence` 按声明的 order 比较，不排序掩盖差异。无 `ORDER BY` 的 SQL 不臆造顺序承诺；需分页稳定性时在 API/profile 中明确完整排序键和重复行定位规则。
7. 规范化只允许删除已列出的非语义字段，如 wall clock、临时绝对路径、随机会话 ID。不得删除 diagnostics、coverage、NULL、重复边、来源或失败状态。
8. 完整比较应同时核对 counts、分区摘要和总摘要；fixture 做逐值比较，发现差异保留首个来源/行/字段定位。摘要不是绕过完整消费的许可。
9. 原始代码/资源指纹沿用现有算法和真实字节区间，并携带算法版本。新建的“语义代码指纹”另设字段，不得覆写 raw fingerprint 来获得表面等价。

### 7.3 证书完成与负缓存

合法分页可以复用同一 snapshot，但完整报告证书必须确认所有页已消费，未截断、无剩余，来源和事实范围始终一致。重复取页、并发取页、token 跨 snapshot、过期 token、取消后继续读取都要有明确测试。

缓存键至少包含输入内容与 occurrence 集合、选择/验证策略、schema/事实算法、查询语义、解析世界及依赖。对于阴性结论还要记录其覆盖范围；新增 split、类定义、bootstrap/资源依赖或 classpath 变化后必须失效。取消、预算中断、损坏输入或部分索引不得生成“未找到”的可复用 cache entry。

## 8. SQL 与 typed IR 等价验收

### 8.1 必须同时验证关系语义与 HostLab profile

类型化核心与 SQLite 桥必须使用同一来源/事实契约，但不要求逐字复刻一套未公开的 SQL 引擎。先冻结真实 HostLab 必需的表、列、操作符、查询模板和返回类型，再扩展产品能力。任何重要 query 只通过“能解析”或 tiny fixture 都不足以通过 HL-MVP；必须在完整 profile 上全量比较。

至少测试：NULL 三值逻辑、重复行、局部 ID join、字符串精确比较、LIKE/ESCAPE/case/collation、IN、EXISTS/NOT EXISTS、聚合、排序、LIMIT/OFFSET、CTE/子查询和实际使用的临时对象/会话规则。动态 SQL 由明确的只读白名单或 AST 检查限制；不要用字符串包含判断代替 statement 语义。

SQLite `xBestIndex` 从可用 constraints/所需列/排序信息获得输入，并返回选定计划、参数约定、cost/rows 等。仅当语义确实执行完整时设置 `omit`，仅当输出真正满足时设置 `orderByConsumed`。近似索引、前缀候选和 bitmap 命中须保留残余验证；局部 method index 不能被声明为全局唯一键。[S13]

### 8.2 必做属性测试

- 同一 QueryIR 在全扫描参考执行器与优化执行器上产生相同 bag/sequence。
- projection、predicate pushdown、join 重排、批次大小和线程数改变不改变结果与覆盖。
- 集合化候选可以内部去重，最终引用重数按关系语义恢复。
- 索引完整/渐进/未建的三种路径都不产生假阴性；未完成索引要回退到受检扫描或明确未完成。
- 同一查询在 cold build、warm snapshot 和重启后持久索引上得到相同证书。
- SQLite 无法安全下推的谓词保留残余执行，不因性能目标静默放宽匹配规则。

DuckDB 如果后续加入，另做批次、NULL、类型、排序/聚合和内存预算适配测试；C API 投影下推不能被泛化为任意 WHERE 下推，稳定 C 扩展 ABI 与内部 C++ 扩展兼容性也必须分开声明。[S14]

## 9. 差分、属性、fuzz 与故障注入

### 9.1 语料分层

| 语料层 | 用途 | 必须记录 |
| --- | --- | --- |
| 手工最小向量 | 精确验证结构、边界、指令和状态 | 期望字节/字段/错误位置及推导依据 |
| 编译/装配生成 | 覆盖真实编译器编码形态 | 生成器版本、源代码、参数、输出 hash |
| 公开 APK | 实际长度/分布/多 DEX/资源 | 固定 URL、版本、许可/再分发约束、SHA、成员 manifest |
| 授权 HostLab 样本 | 完整业务报告和迁移 | 固定 APK hash、工具 hash、查询/规则 profile；不得将私有原件随公开 release 分发 |
| 历史失败回归 | 防止已修错误复发 | 最小化输入、原 failure、修复 commit 与不变期望 |
| mutation / fuzz corpus | 探索未知边界与状态组合 | seed、fuzzer/toolchain、目标、预算、覆盖与 crash artifact |

不能只有真实 APK：它们不容易覆盖溢出、截断、NULL 或代理字符。也不能只有两个短行重复：它们不能代表实际长 descriptor、复杂引用和资源分布。

### 9.2 Fuzz 目标必须窄且可复现

至少拆分 archive inventory、ZIP64/descriptor、MUTF-8/LEB、DEX tables、encoded values、code/payload/handlers、041、AXML、ARSC、持久索引 reader、批协议 decoder、QueryIR validator 和分页/cancel 状态机。

默认 Rust 核心执行单元/属性测试和覆盖引导 fuzz；实际使用的 Rust fuzz/sanitizer 工具链独立锁定。如果检测配置需要 nightly，它只属于测试工具链，不改变发布用 Rust stable/MSRV 契约。AOSP/SQLite 等 C/C++ FFI 依赖使用实际可用的 ASan/UBSan 配置；不得将 C/C++ UBSan 的覆盖范围宣称为整个 Rust 程序的 UB 证明。并发与生命周期另用实际支持的 TSan 或相应平台工具，不能把相互冲突的 sanitizer 配置硬塞进同一构建。MSan 等需要完整受控依赖的配置作为后续专项。libFuzzer 官方要求目标能容忍任意输入、避免直接退出进程、尽量确定且不遗留线程；这些适用于本项目目标设计。[S15]

结构 mutation 应同时包括两类：保留 checksum 失配以覆盖导入拒绝；修复 checksum/长度后深入内部结构。否则大量 fuzz 时间可能只在头部校验提前返回。将低层 parse 目标与完整导入目标分开，避免为 fuzz 永久关闭生产校验。

必须把 crash、越界、UB、无界内存、无进展循环、错误成功、错误阴性结果都视为失败。0 crash 和覆盖率百分比不是格式完备证明；CI 报告要列目标、语料和可达分支，而不是单写“fuzz passed”。

### 9.3 Metamorphic 与失败路径

- 相同 DEX 在 stored/deflate 包装下，来源包装身份可不同，规范化 DEX 事实相同；不能要求整个来源证书 hash 相同。
- 输入顺序改变时 occurrence/解析优先级按声明规则改变；无顺序语义的事实集合在显式来源映射后相同。
- 增加无关资源不改变 DEX 内局部纯事实；全 APK ContentId 和资源覆盖证书仍需改变。
- 同一符号在不同 DEX 重复定义时不丢行；存在冲突必须进入解析世界/业务判断。
- 杀死生产索引的 worker、磁盘写满、损坏 sidecar、版本不兼容、发布前崩溃、一个 singleflight 等待者取消，都不能留下被当成完整的索引。
- 多读者持 lease 时更新 generation、释放外层 snapshot、回收缓存、卸载插件，都不能使仍有效的 batch 失效。
- 固定时机注入取消/超时/内存预算失败；客户端得到终态、实际 coverage、未完整交付状态与明确资源清理，不收到伪造的空成功。计算/事实已完成而传输取消时，保留其实际完成度，不强制降格事实覆盖。

## 10. 公平性能比较：A0 / A1 / A2 / B0 / B1

### 10.1 各组定义

| 组 | 固定内容 | 用途与边界 |
| --- | --- | --- |
| A0 | DexSQL 0.1.0 + 当前固定 HostLab | 相对当前生产路径的改善 |
| A1 | DexSQL 0.1.1 + 等价原 HostLab 路径 | 剥离上游已经完成的改进 |
| A2 | 现成且已通过兼容验证的机器接口/外层改造 | 比较 compact/JSON/批量接口等可部署选项；不可假定等价或可用 |
| B0 | MeguvizDexDash，保持原消费契约的替换模式 | 衡量同接口替换；producer/计划等也可能变化，不能自动归因纯 parser |
| B1 | MeguvizDexDash + 批接口 + HostLab 适配/必要聚合改造 | 衡量完整职能替代及其净收益 |

A2 需记录具体协议、版本、选择理由与完整结果 profile。若某现成接口不能完成全部必需查询，它仍可作为该组件对照，但不能称可替换的端到端基线。B0/B1 无实现前不得填入预测值冒充 trial。

### 10.2 必须同等的条件

比较前固定输入 SHA、来源集合、选择与校验策略、查询/规则 bundle、完整返回 schema/类型/顺序、结果消费方式、编译优化级别和资源上限。必须完整消费所有行并得到相同证书。

线程数采用**总资源预算**：不能只把引擎 `threads=2` 写相同，却让其中一方另开无限解压/SQL/插件线程。记录请求线程数、实际线程峰值、CPU affinity、cgroup quota、NUMA/架构和并发任务；允许不同合理调度，但同总预算。

如果某实现必须预建索引或重编码，首次构建成本必须进入相应 cold 场景；另列 warm 收益和 amortization。不能预先给 B 准备全部 sidecar，然后拿其驻留查询对比 A 的首次打开。

### 10.3 缓存与时间窗口分开命名

| 场景 | 定义 | 禁止混用 |
| --- | --- | --- |
| process-cold / OS-warm | 新进程，无自有索引/结果缓存，OS 文件缓存保留 | 不能称 cold-disk |
| index-cold | 从原输入建立所有本次必需事实/索引 | 不把提前构建移出计时 |
| persistent-index warm | 新进程验证并打开已存在完整索引 | 包含索引身份校验、映射和必要恢复 |
| resident warm | 同 snapshot 已在进程内，多次查询 | 首次查询与重复查询分列 |
| result-cache hit | 直接复用相同语义完整结果 | 不当作查询算子速度 |
| cold-disk / staging | 专门隔离环境下确认缓存状态，包含所声明 I/O | 不在共享开发机上擅自清系统缓存；不能未验证便声称冷盘 |
| incremental | 从明确旧 snapshot 到新版本，含 diff/hash/依赖失效与重绑 | 分母为 B incremental / B full，不能再乘冷启动倍速 |
| service total | 队列、上传/下载、staging、worker、发布 | 与静态 worker E 分开报告 |

producer 捕获、consumer 回放、真实 pipe 联动、完整 worker 是四种不同测量。两端可重叠执行，孤立耗时不能简单相加；吞吐提升也不能与耗时下降混用分母。

### 10.4 统计与运行组织：拟定项目策略

- PR 只做功能/性能 smoke，不把 3–5 个有噪声的短样本当作稳定发布结论。
- 稳定性能 runner 上采用预先确定的交替/随机配对顺序；固定 warmup 次数，在运行前声明 trial 数、排除条件和时间预算。
- 完整 release 比较建议每个关键 fixture/profile 至少 10 个配对 trial，并在第二个独立时间块复测。大审计预算不足时明确降级为探索性结果；不得通过选择最好一轮放行。
- 同时保存原始逐轮 wall/CPU/资源/结果证书、版本中位数和配对速度比。`median(A)/median(B)` 与 `median(A_i/B_i)` 不混写。
- 如使用置信区间，方法和配对/会话分组单位必须公开；驻留 session 内的重复查询不是相互独立的新 session。
- p95/p99 需专门尾延迟 workload 和足够独立请求。建议至少 100 个请求作为初步 p95 描述门槛，仍要报告样本量与不确定性；这不是统计可靠性的普遍保证。历史单次完整测量不能生成 p95。
- 正确性失败、超时、崩溃、OOM 都是 trial 结果，不能删除。环境干扰可以标记，但原始记录保留，按预先规则重跑整个配对块。
- CPU benchmark 串行使用专用资源，不与 fuzz、编译或其他团队基准并跑；磁盘/cache 试验另列隔离条件。

## 11. 已有测量与 37% / 47% 条件目标

### 11.1 当前完整 worker 基线

已恢复 GitHub Actions run `40067936875` 的原始附件，并核对其 22 个工具 SHA 与 HostLab `8782f43d537c442905123e35af325c412caa5188` 相符。原始 `verification.json` SHA-256 为 `bf4ca0cd3df35dab13ed1a83dedf92e5b6dfa485e4d48611d424cf8462b01f7d`。[H1][H2]

测量为 Linux Azure x86_64、4 CPU、DexSQL 0.1.0、原生线程 2；新 worker 顺序执行、OS 文件缓存保留。每个当前样本仅一条完整测量，不能从中估计方差或 p95。

| 互斥时间段 | BIL 9.17.0 / 9170100 | BIL 9.16.1 / 9161100 |
| --- | ---: | ---: |
| P：显式准备 | 1.442956 s | 1.308335 s |
| S：结构分析复合阶段 | 13.663421 s | 11.911596 s |
| F：surface 复合阶段 | 56.525247 s | 50.801524 s |
| R：native 内未分项余量 | 0.253425 s | 0.241183 s |
| O：native 外检查、门禁、报告与验收等余量 | 22.745093 s | 21.309582 s |
| **E：完整 worker** | **94.630143 s** | **85.572220 s** |

原 APK SHA：9.17.0 为 `f0f880e841d017db335b3919e6d4792961f2e08aa9993da661b626d52cfcb955`；9.16.1 为 `41efb1c9acb07badab5296953fb3da1def6925e2b34662120ca96df9d17bbfb2`。两者分别 35/33 个 DEX，当前规则负载 647/635 次逻辑查询；这些计数只描述该固定 profile。[H1]

S/F 均包含 SQL、传输、Python 处理等复合成本；F 还含原始代码和资源指纹。显式 P 约 1.5% 不代表全部解析仅占 1.5%；延迟事实可能出现在后面。O 不能全部叫作可删除的 Python 门禁时间。E 不含最初 APK 下载、云端排队、环境恢复、AI 分析与 artifact 上传。[H1][H2]

### 11.2 条件预算，必须计入新开销

在相同窗口、其余成本保持原值时：

```text
E_new = P + R + O + S/sS + F/sF + Δ
time_reduction = 1 - E_new/E_A0
speedup = E_A0/E_new
```

`Δ` 是未包含于上述新阶段计时的额外净开销；真实实现应直接测完整 E，不能把验证、索引构建、生产端编码或插件启动藏在 Δ 之外。各阶段必须互斥，内部嵌套 timer 不可重复相加。

| 条件，暂取 Δ=0 | 9.17.0 预算 | 9.16.1 预算 | 对各自 A0 的整体降时 |
| --- | ---: | ---: | ---: |
| S/F 各 1.5× | 71.23 s | 64.67 s | 24.4–24.7% |
| **主目标：S/F 各 2×** | **59.54 s** | **54.22 s** | **36.6–37.1%，约 37%** |
| **挑战目标：S 2×、F 3×** | **50.11 s** | **45.75 s** | **46.5–47.0%，约 47%** |

这是同两个样本的代数预算，不是置信区间，也不是自研 B 已达成成绩。旧机器的约 60/55 秒、50/46 秒不能直接套到新机器；M0 应同机重测 A0/A1/A2，按新的互斥 S/F 阶段测量与上述公式重新生成预算。每增加 1 秒新开销，对历史两个分母分别损失约 1.06/1.17 个百分点。[H3]

若只加速某阶段中关键路径占比为 a 的核心，核心速度为 r，其阶段剩余比例为 `(1-a)+a/r`。核心快 2× 不等于 S/F 整体快 2×。B0 即便保持原消费接口，也可能改变 producer/计划/事实建立，不能只凭 A0/B0 总时间宣称纯 parser 贡献。

约 37% 的目标适用于 B1 完整职能替代。若 A1/A2 已更快，自研增量必须对它们另算；不把相对旧 A0 的全部改善记为自研独有价值。尚无 BIL 全 profile 的 A1/A2/B0/B1 实测，必须在迁移阶段补齐。

### 11.3 公开样本局部结果及不可外推边界

NewPipe v0.28.6 APK，SHA-256 `e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58`；完整查询返回 55,763 行、5 列，包含长 descriptor。所有下表结果都来自相同完整有序数据，非新 DEX 核心实测。[H4][H5][H6]

| 证据 | 已测结果 | 只能支持的结论 |
| --- | --- | --- |
| consumer 内存回放 | 原 HostLab AST decoder 846.784 ms →列批原型 124.889 ms；中位数比 **6.78×**，组件降时 **85.25%** | 这一个预编码消费环节可减少大量表格/hex 解析成本 |
| 表示字节数 | hex 305,380,092 B →二进制 10,836,227 B；减少 **96.45%** | 表示体积减少，不是进程 RSS 或整体引擎内存降幅 |
| 紧凑 JSON 参照 | 10,632,455 B，比本二进制原型略小约 1.9% | 本轮未证明二进制优于 JSON；两者消费性能未直接对照 |
| 真 CLI + 原 CliSession 联动 | 0.1.0/0.1.1 的 5 轮配对速度比中位 **2.88×**；范围 2.74–3.21× | 现有上游升级对该单条完整查询管道有收益 |
| 同联动各版本时间中位 | 4.035/1.289 s，比值 **3.13×** | 与配对倍速中位的统计量不同，不能替换为“2.88 的精确值” |
| 辅助短行 100k 回放 | 约 **1.56×** | 数据形态会显著影响结果，不能给所有查询统一 6.78× |

consumer 回放保留原 `read/line/table/rows` 方法 AST、64 KiB reader 和 8 块有界队列；双方最终生成全部相同的 `str/None` 字典列表。其输入已预编码驻内存，**排除** APK/DEX 解析、索引、SQL、生产端编码、真实内核 pipe 和完整审计规则。完整 live pipeline 则包含真实进程和 pipe；它来自 0.1.0→0.1.1 升级，属于 A1，不属于 B。

不能将 6.78×、2.88× 相乘或相加；不能把它们乘到 BIL surface 或完整 worker。也不能把 96.45% 的字节减少改写为同等内存收益。新协议必须独立测生产端、背压、传输、消费与最终完整 E。

## 12. 必测 workload 与资源指标

### 12.1 Workload 集合

| ID | 场景 | 结果契约 |
| --- | --- | --- |
| W01 | 仅导入/验证/建立基础事实 | 完整 inventory、来源和验证层；不能只打开 magic |
| W02 | 精确类/方法/字段/字符串、小结果定位 | 固定 NULL、重复与来源语义 |
| W03 | 字符串组合、caller/callee/field xref、候选优先 | 保留重复引用、动态调用类别与未知项 |
| W04 | 多表 join/聚合/排序及全部 HostLab 重要查询模板 | SQL profile 完整差分 |
| W05 | 大结果：短/长/偏斜字符串，1k/10k/100k 与真实 APK | 相同完整 producer→consumer 物化结果 |
| W06 | 方法反汇编、CFG/def-use 首次与复用 | 同层能力、分析世界和覆盖 |
| W07 | 两个固定 HostLab 全 profile | 完整 canonical 报告与 E/S/F 等计时 |
| W08 | 持久索引首次构建、重启 warm、失效重建 | 索引验证/修复开销入账，证书一致 |
| W09 | 同机并发 1/2/4 个任务，公平总预算 | 吞吐、尾延迟、饥饿、取消和真实物理内存 |
| W10 | 多版本增量、跨 APK 查询 | 全量 B 与增量 B 独立分母，计入 hash/重绑/全局工作 |
| W11 | 资源与可选格式插件 | 已声明版本，不将 unsupported 排除后仍声称全覆盖 |
| W12 | 取消、预算、坏缓存、坏输入 | 有界失败与无错误成功；这不是吞吐排行榜 |

### 12.2 资源测量口径

同时保留 wall、进程树 user/system CPU、峰值/采样内存、映射/私有内存、读写字节、page faults、线程峰值、临时磁盘和持久索引体积。不同 OS 指标定义不同，报告需写明采样方法、间隔、缺失项和是否含子进程。

- RSS 相加可能重复计算共享映射；如要宣传同机共享收益，应优先使用合适的 PSS/USS、系统/容器总占用及私有分项，解释不可读进程或采样漏峰。
- Windows working set/commit/private bytes 与 Linux RSS/PSS 不直接当同一指标排名；macOS 同理。
- 容器 memory.current/peak 可能包含 page cache 和其他进程，不等于某引擎独占内存。
- 同机多个 worker 可共享文件背书页；不同 GitHub runner/云主机不能共享物理页，不能套用同机内存公式。
- mmap、缓存和列批改善需包含全程最坏峰值。旧峰值组成不能推出新峰值；新增解压、重编码或建索引可能让峰值迁移。
- 持久缓存应计存储体积、首次写入、加载验证、命中率、失效和回收成本；低命中场景也需测。

历史两个 worker 采样进程树 RSS 峰值约 1.25/1.19 GiB，0.5 秒采样，既不是精确峰值也不是 DexSQL 单进程值；它们只能保留为同口径历史参照。[H1] 本项目暂不把未经完整实测的固定内存降幅设为宣传收益。

## 13. 跨平台、ABI 与生命周期矩阵

### 13.1 产品发布层级

| 平台 | 首版策略 | 最低验证 |
| --- | --- | --- |
| Linux x86_64 | Tier 1 | 固定 Rust stable/target/linker；原生依赖固定 GCC/Clang；原生正确性、可用 Sanitizer、完整 HostLab profile、持久/IPC/性能 |
| Windows x86_64 | Tier 1 | 固定 Rust stable 的 MSVC target 与 MSVC/SDK；原生安装/ABI/路径/映射/worker/完整 profile；同平台性能基线 |
| macOS arm64 | 随后独立验收才 advertised | 固定 Rust/Apple 工具链、实际页大小、dylib/worker、数据与完整 profile、内存口径 |
| Linux arm64 | 后续独立能力 | 对齐、原子/向量实现、持久格式跨架构读取、原生正确性及性能 |
| macOS x86_64 / Windows arm64 | 按需求设后续目标 | 不因 C++ 可编译或 emulation 成功便宣布原生支持 |

构建成功、交叉编译成功、模拟器运行成功和原生发布验收分别记录。首版 Tier 1 任一平台缺失完整 profile 证据，就不能宣布两平台等价生产可用。

### 13.2 必测系统与公共 ABI 契约

- 长路径、空格/非 ASCII、只读目录、低权限、临时目录、磁盘满、映射偏移/长度、文件打开共享与延迟回收。
- 16/32/64 位边界、未对齐输入、不依赖 x86 容忍非对齐访问；文件持久格式明确字节序和相对偏移，不存裸指针/`size_t`/STL 内存布局。
- 创建方提供释放函数；异常、STL 容器、allocator 和编译器布局不跨 C ABI。结构有 size/version 协商，未知必要能力明确拒绝。
- 有效调用生命周期内，batch/字符串 view 的 lease 可验证；释放外层 snapshot 不得提前失效仍合法持有的 batch。非法调用是否可诊断应按 ABI 契约测试，不凭空承诺任意悬空指针安全。
- query 并发、cancel、close、插件卸载与 callback 生命周期的合法组合；旧插件/旧客户端对新库的协商结果。
- 插件崩溃、worker 被杀、IPC 半帧、重复/乱序消息、超大长度、输出阻塞、客户端断开；不能将 worker 失败转换为完整空结果。
- singleflight 的等待者取消不影响仍需结果的其他请求；超时/失败的生产任务不发布完整 cache entry。

若与另一 DexMeguviz 项目共用解析核心，分别固定公共核版本、MDD ABI、schema、IR、持久格式与平台包。共用语料和契约测试，避免两边复制 parser；手机生命周期/JNI 测试不是桌面多进程和 Windows 发布测试的替代。

## 14. CI 关卡与 release 策略

### 14.1 G0–G6 的可审查产物

| Gate | 产物与执行范围 | 通过条件 |
| --- | --- | --- |
| G0 契约与基线 | capability manifest、来源/结果 schema、SQL profile、fixture/oracle/dependency locks、A0/A1/A2 harness 设计 | 字段和状态无冲突；每项支持声明可追踪到测试；默认 SQLite 桥经实际查询可行性验证 |
| G1 基础 parser | 035/037/038/039/040、APK stored/deflate/ZIP64；最小/真实/损坏语料；Sanitizer | 无越界/UB/错误成功；独立向量通过；未知格式正确拒绝 |
| G2 事实与查询 | 指令关系、multiplicity、QueryIR 全扫描对照、SQLite 必需语法/NULL/顺序 | 全部已承诺 query 完整等价；索引/线程/批次变化不改证书 |
| G3 HL-MVP shadow | 原工具/规则固定，完整两个授权样本与 public fixtures；业务发布副作用隔离 | 20 组旧证据及新证书全部通过；全部重要 query profile 达标；不足覆盖不得称 HL-MVP |
| G4 常驻与持久 | snapshot/lease、并发、取消、缓存失效、崩溃恢复、跨平台索引 | 不发布半成品、不误负缓存；预算有界；两个 Tier 1 原生通过 |
| G5 性能发布 | A0/A1/A2/B0/B1 同机等价比较、完整 worker、资源、逐轮数据 | 满足预注册阈值；失败/缺失 fixture 明确阻塞相关支持/性能声明 |
| G6 可选能力 | 041、资源语义、CFG/def-use、CompactDex/VDEX/OAT、DuckDB、后续平台各独立 gate | 独立版本/语料/资源预算通过；不开启未验能力；不得拖累默认路径而无记录 |

G3 的 shadow 只能生成隔离对照产物；不得双份写业务缓存、重复推送报告、改变调度状态或触发 AI 发布。授权样本取不到时保留 public/tiny 结果，G3 标 `blocked`，不能以它们代替完整 HostLab 验收。

### 14.2 CI 频率与预算：拟定默认策略

- **每个 PR**：两个 Tier 1 的相关编译/单元/契约/损坏输入回归；Linux 上已支持的 Rust 检测配置及 C/C++ FFI ASan/UBSan；改动涉及的 differential；短 fuzz smoke。耗时上限按 CI 配额设置，避免以超时默认为通过。
- **Nightly**：所有格式与失败语料、跨线程/批次属性、持久故障、TSan 配置、固定预算 fuzz、public profile。实际执行秒数、覆盖变化和未运行项进入报告。
- **性能专线**：固定 runner 串行执行，保存每轮原始数据；不在共享 PR runner 上因 3% 波动自动宣称提速。
- **Release candidate**：完整双 Tier 1、所有 advertised capability、授权完整 HostLab profile、独立时间块性能复测、依赖/ABI/持久兼容、取消与回滚演练。
- **持续 fuzz**：初始建议每个关键目标 nightly 10 分钟、release 前累计至少 2 小时有覆盖运行；这是预算策略，不是安全/完备性保证。时间与覆盖不足时显式列为风险，不伪造通过。

### 14.3 性能退化与默认切换门槛：项目策略，不是已知事实

以下全部为 **proposed 项目策略**，作为 M0 的初始数值建议，确认后写入版本化 `performance_policy`；只能通过有证据的 ADR 调整并说明原因，不能看到不利结果后默默改门槛。正确性门禁 mandatory，不因性能策略调整而豁免。

| 指标 | 建议动作 |
| --- | --- |
| 任意结果/coverage/原始指纹不一致，或新 crash/UB/错误成功 | 无条件阻塞相关能力发布，不用速度抵消 |
| 相对上一已发布 B，关键 profile 的配对中位 wall 退化 >5% | 性能告警，保留全部数据，调查并复测 |
| 同一关键 profile 退化 >10%，且两个独立时间块复现 | 阻塞默认发布；必要修复可显式批准降级并更新说明，不能偷偷换 fixture |
| p95 workload 已达到约定样本量且相对基线退化 >15%，两个块复现 | 阻塞交互路径默认切换；没有足够请求则报告未验证，不计算虚假 p95 |
| 同口径进程树/容器峰值或持久索引体积退化 >10%，两个块复现 | 阻塞默认发布，除非有事前批准的功能/内存 tradeoff 和预算调整 |
| 任意配置硬资源预算、超时或输出完整性超限 | 按契约失败；不得接受只截断结果的“性能修复” |

成为 HostLab 性能替代 release 时，B1 必须对**同环境中最强、完整兼容且可部署的 A0/A1/A2**有稳定正收益，不能只赢过 A0。拟定门槛是：关键完整 audit 与 bulk 负载均至少达到 **10% 配对中位耗时下降**，并在独立时间块复现；其他必需负载不得出现 **超过 5% 的可复现退化**。baseline 的选择须逐 workload 公开，不能拿某接口在其他不相干负载的弱项充当对照。

若未达到该门槛，仅发布明确标识的功能预览/研究版本，保持 opt-in，说明正确性、独立维护等其他价值，不宣称性能替代成功。上一张表的告警/阻塞线用于相对既有 B 发布的维护回归；本段另管 B1 相对现成方案的默认切换资格，两项都要满足。

约 37% 是 B1 相对 A0 的首轮目标预算，约 47% 是挑战目标；它们不是所有查询/平台的无条件硬保证。发布可以只达到其中部分目标，但必须准确标明未达成的目标及已支持范围；若发布宣称“整体约 37% 改善”，必须拿到同机、全证书、完整 E 的对应实测。

校验修复导致增加工作量时，应保留修复前后语义差异，不通过关闭修复维持性能线。更严格正确性 profile 的速度与旧宽松 profile 分列，同时提供等语义比较。

## 15. AI 工程执行与验收交接清单

执行 AI 每次提交与相关能力对应的证据，而不是只说“所有测试通过”。以下是需要实现/产出的工具契约和文件角色，不表示这些工具现在已经存在：

1. **Manifest**：capabilities、fixtures、oracles、query profiles、toolchain/dependency locks、performance policy，全部版本化。
2. **Runner**：能选择 fixture/profile/引擎/线程/缓存状态；运行前打印完整身份和计划；结果与 stdout/stderr 分离；失败有非成功退出状态。
3. **Comparator**：读完整结果，按声明的 bag/sequence/typed schema 生成证书；差异输出来源、行和字段，不自动改 golden。
4. **Fuzz/regression**：新增目标、seed、回归输入及预期状态；每个已修 bug 增加最小反例。
5. **Trial records**：保存原始逐轮数据、证书 hash、环境、顺序、缓存、预算、完整消费和失败记录。
6. **Release evidence**：每个 advertised 能力链接 gate 结果、平台、来源 commit 和 corpus 摘要；未验证项明确列出。
7. **执行总结**：具体执行了哪些测试、哪些没执行及原因、发现和修复了什么、剩余风险、是否满足默认切换条件。

如果依赖、私有样本、平台 runner 或独立 oracle 不可用，先完成可执行部分，并将对应 gate 标 blocked/unsupported；不能生成假测量、伪造截图、合成“真实大 APK”结论或声称已经全兼容。本文编写阶段只审阅既有材料，没有新增 CPU benchmark，也没有实现 parser 或业务代码。

## 16. 主要未消除风险

1. **已有格式类名与实际 loader 能力不同**：stock AOSP external API 还会关闭完整验证；跨平台构建、校验边界和 ABI 必须独立完成。
2. **完整性最容易在优化中丢失**：041 共享尾区、重复 ZIP/实体、局部 ID、引用重数、NULL、MUTF-8、动态调用和部分索引，都会造成看似合理的假阴性。
3. **独立 oracle 不足**：复用同一个 parser 的多个工具不能独立证明正确。041、历史运行时产物和稀有资源布局尤其需要额外向量。
4. **接口收益可能大于内核收益**：公开数据已证实表格/hex 膨胀，但 0.1.1 已做输出优化。B 必须与 A1/A2 比较，不把消费端原型 6.78× 当核心目标。
5. **历史完整样本统计量不足**：94.63/85.57 秒各只有一次当前测量；37/47% 是阶段预算，需要同机完整 B1 试验，不能提供 p95 或置信承诺。
6. **资源节约未实测**：映射共享、缓存和批接口都可能把峰值转移到构建或重编码阶段；独立云 runner 没有同机页共享收益。
7. **平台宣称容易过度**：Linux/Windows 首版都须原生验收；macOS/arm64 后续通过才列支持，Android/JNI 测试不能替代。

## 17. 依据与复核入口

下列链接是规范、固定源码或原始证据；项目策略与待实施设计不能写成来源已经保证。工程包内的轻量证据及其 SHA-256 以 [evidence/index.json](../evidence/index.json) 为入口；AOSP 文件固定来源与散列在 [主源码清单](../evidence/aosp_source_manifest.json) 和 [补充源码清单](../evidence/aosp_additional_manifest.json)。原工作区路径用于追溯，不要求新工作区存在同样的 scratch 目录。

### 官方规范与固定源码

- **[S1]** [AOSP DEX format](https://source.android.com/docs/core/runtime/dex-format)；2026-10-26 复核 041 实验说明。稳定保存规范快照/摘要应纳入工程 evidence lock。
- **[S2]** ART `6484611fd45e69db9f33f98bfd6864014b030ecf`：[standard_dex_file.cc](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/standard_dex_file.cc)、[dex_file_verifier.cc](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_file_verifier.cc)。
- **[S3]** [PKWARE ZIP APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)，已复核记录/data descriptor/ZIP64 相关段；设计引用其格式，不复制全文。
- **[S4]** [AOSP Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode)。
- **[S5]** 同一固定 ART：[dex_instruction_list.h](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_instruction_list.h)，特别是 `INVOKE_POLYMORPHIC`、`INVOKE_CUSTOM` 与 method handle/type。
- **[S6]** 同一固定 ART：[dex_file.cc](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_file.cc)、[dex_file.h](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_file.h)，容器头、地址与 checksum 范围。
- **[S7]** [libdexfile/Android.bp](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/Android.bp)。
- **[S8]** [dex_file_external.h](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/external/include/art_api/dex_file_external.h)、[dex_file_ext.cc](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/external/dex_file_ext.cc)，稳定 C ABI 与 `verify=false` / `verify_checksum=false` 的边界。
- **[S9]** frameworks/base `99b01a65cc4c104933788b3143285ab6bae65827`：[ResourceTypes.h](https://android.googlesource.com/platform/frameworks/base/+/99b01a65cc4c104933788b3143285ab6bae65827/libs/androidfw/include/androidfw/ResourceTypes.h)、[BinaryResourceParser.cpp](https://android.googlesource.com/platform/frameworks/base/+/99b01a65cc4c104933788b3143285ab6bae65827/tools/aapt2/format/binary/BinaryResourceParser.cpp)、[XmlDom.cpp](https://android.googlesource.com/platform/frameworks/base/+/99b01a65cc4c104933788b3143285ab6bae65827/tools/aapt2/xml/XmlDom.cpp)。
- **[S10]** [Microsoft MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile) 与 [Apple mmap](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mmap.2.html)。
- **[S11]** 固定 ART：[dex_file_loader.cc](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_file_loader.cc)、[vdex_file.h](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/runtime/vdex_file.h)、[oat_file.h](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/runtime/oat/oat_file.h)。
- **[S12]** 历史 ART `34f62af4d6425087667b7eb3998fcf58d61a2fa6`：[dexlayout.cc](https://android.googlesource.com/platform/art/+/34f62af4d6425087667b7eb3998fcf58d61a2fa6/dexlayout/dexlayout.cc)、[compact_dex_writer.cc](https://android.googlesource.com/platform/art/+/34f62af4d6425087667b7eb3998fcf58d61a2fa6/dexlayout/compact_dex_writer.cc)。
- **[S13]** [SQLite virtual tables](https://www.sqlite.org/vtab.html)、[sqlite3_vtab_in](https://www.sqlite.org/c3ref/vtab_in.html)。
- **[S14]** 已读取的版本化文档：[DuckDB 1.4 C table functions](https://duckdb.org/docs/1.4/clients/c/table_functions)、[1.4 C++ API](https://duckdb.org/docs/1.4/clients/cpp)、[2.0 release cycle](https://duckdb.org/docs/2.0/dev/release_cycle)。实际工程采用版本仍须锁定和独立测试。
- **[S15]** [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html)，目标与 corpus/sanitizer 方法；fuzz 时间门槛为本项目策略。

### HostLab 和本轮原始量化证据

- **[H1]** [原始 Actions run 40067936875](https://github.com/jichuo1/innocent-lab-host-analysis/actions/runs/40067936875)；包内 [原始 verification](../evidence/hostlab_verification.json) 与 [恢复/核对结果](../evidence/hostlab_measured_basis.json)。原工作区另存 `research/quant_v3/artifacts/40067936875/remote-output/verification.json`、receipt、`hostlab_measured_basis.md/json`。
- **[H2]** HostLab `8782f43d537c442905123e35af325c412caa5188`：[verify_audits.py](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/verify_audits.py)、[native_audit.py](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/native_audit.py)、[native_cli.py](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/native_cli.py)、[native_surface.py](https://github.com/jichuo1/innocent-lab-host-analysis/blob/8782f43d537c442905123e35af325c412caa5188/tools/hostlab/native_surface.py)。
- **[H3]** 包内 [阶段条件模型](../evidence/measured_phase_model.json)；原工作区 `research/quant_v3/measured_phase_model.py/json` 与 `HostLab_DexSQL_Quantified_Performance_20261026.md`。模型是条件预算，不是新引擎测量。
- **[H4]** 包内 [真实样本 decoder 回放](../evidence/decoder_public_apk_results.json) 与 [合成分布回放](../evidence/decoder_microbenchmark_results.json)；原工作区 `research/quant_v3/decoder_microbenchmark_report.md`、`real_apk_decoder_replay.py`、`decoder_microbenchmark.py`。
- **[H5]** 包内 [真实 CliSession 联动](../evidence/hostlab_public_pipeline.json)，原工作区 `research/quant_v3/hostlab_public_pipeline.py/json`：逐轮完整结果与统计。
- **[H6]** 包内 [生产端捕获对照](../evidence/public_apk_profile.json)，原工作区 `research/quant_v3/public_apk_profile.py/json`，以及 [NewPipe v0.28.6 发布页](https://github.com/TeamNewPipe/NewPipe/releases/tag/v0.28.6)；[DexSQL 0.1.1 发布说明](https://github.com/LSPosed/dexsql-release/releases/tag/v0.1.1)。

发布工程包时应将所需轻量证据和 hash manifest 一同保留，或提供可恢复的固定来源；不要依赖会过期的 Actions 附件下载地址。大 APK/305 MB 捕获帧可按许可与体积策略单独存放，但复现指令、精确摘要和未包含的原因必须随包保留。
