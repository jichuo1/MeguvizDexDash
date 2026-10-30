# MDD-030 实际范围与复现

实现位于 `crates/mdd-query/src/ir/`、`operators/`、`executor.rs` 与 `executor/facts.rs`。通用IR包含Scan、SelectIds、Filter、Project、EquiJoin(inner/left)、Aggregate(count*/count/sum/min/max)、Order、Limit和ReadCodeBytes表达式，不含业务模板或SQL执行器。

请求版本 `mdd.typed-query.v1`、文本版本 `mdd-text-v1`。prepare递归校验所有节点：1024节点/64深度、256列、4096集合元素、256 LIKE token；Schema列ID唯一，display_name可重复。全序要求由明确覆盖全部输出列的Order证明；Project/Filter/SelectIds/Limit保留已证明的顺序。未声明全序的结果不承诺稳定排序。

值显式区分NULL、bool、i64/u64十进制字符串、UTF16 code units、Base64 bytes、完整EntityRef。Eq不隐式CAST，RawBytesEq独立；NULL参与比较为unknown，filter只保留true。JOIN不匹配NULL键，left join补NULL，重复不丢失；SelectIds把请求IDs作集合，但保留输入重数。空全局aggregate返回1行：count=0，sum/min/max=NULL；空分组aggregate返回0行。SUM检查位宽溢出。

字节codec采用标准带padding Base64：拒绝长度非4倍数、URL字母表、空白/换行、非法字符、首/中间/多余padding、padding后续数据、非零未用bits。`AB==`、`AAB=`等即使可宽松解码也拒绝。空bytes=`""`与NULL独立。原始DEX MUTF8由strings.raw_mutf8提供Bytes视图，strings.utf16提供独立无损code-unit视图；没有有损String替代身份或原值。

`native_like_pattern` 只编译明确的原生UTF16通配记法，不解析SQL字符串；对应20项手工与独立Pythonoracle覆盖NUL、孤立代理、代理对、%/_字面量、不同escape、未指定escape及尾escape错误。SQLite/DexSQL方言资格属于MDD-031。

PreparedQuery绑定不可伪造catalog identity、snapshot和catalog_epoch；只能从prepare取得，required_layers由provider schema和表达式推导，调用者不能删掉必要层。所有节点解释记录输入/输出schema、所需层、语义版本、访问候选和顺序要求。零输入、Limit0也先做整计划类型/来源/所需层校验；非法literal实体不会因0行跳过。结果和准备计划对SDK只读。

NativeCatalog持有只读MetadataFacts/DefinitionFacts/CodeFacts的Arc，验证source身份和同Blob lease；不重开文件。metadata-only范围只允许对应池事实，结构/代码缺失明确IncompleteFacts。原始读取只接受MethodDefinition，匹配定义的code offset和insns长度到完整code-map事实，按byte范围借用raw insns；abstract/native与存在空body不混淆。注册任意小表的MemoryCatalog明确是generic SDK/test数据，不能据其ready列表签生产事实资格。

执行模式包含流式scan/filter/project/membership、保留重数的JOIN候选、受检查点控制的merge排序；参考模式先全扫描/物化，使用嵌套循环JOIN、线性membership/group候选、insertion排序。共享精确类型/值/聚合原语不构成独立oracle，外部Python人工小表和pattern/codec oracle负责独立核对。

每个scan/算子/表达式/LIKE cell/JOIN match/聚合/排序比较提供work检查点，hook可接后续session取消/超时。steps、输出行、cell和累计保守buffer admission受限；该buffer计数是逻辑工作预算，不是进程RSS或allocator硬上限。最终输出收集仍是内存结果，不提供M4分页/传输终态；MDD-034继续完善预算、取消和终态。这轮不签持久索引、SQL、HostLab/ART、MCP或性能资格。

复现：

```text
python artifacts/mdd-030/verify.py
```

脚本保存实际命令、stdout/stderr、编译器、源码前后hash和测试二进制身份。初始测试编译错误及Clippy修复前记录保留，最终scope以最新receipt为准。回滚由主代理按本任务新增文件及其Cargo/lib接线撤回，不重置其他任务或删除历史证据。
