# MDD-021：物理起点、未引用布局与真实定义不能混同

## 现象

只证明 class_data_off/type_list offset 落在 section 范围内，仍可能把 item 中间的零字节当作空结构。首次按物理 map count 行走 class_data 时，又只跳过了未被 class_def 引用项的编码值；SDK37 证实这些物理项的非法索引、delta 与组标志也需要拒绝。

## 证据

生成器、手工语义期望及独立 Python 解析位于 tests/fixtures/definitions/。40 个语料的身份在该目录 manifest.json。SDK37 的两组只读 -f 对照保存在 orphan-sdk-probes/ 和 orphan-sdk-probes-v2/；修复前 native probe 明确打印非法 orphan-field-index accepted=true，断言失败退出101。最终修复后的真实命令、输出及源码身份在 definition-conformance.json 和 final-orphan-validation/。

固定 A0 Windows DexSQL 0.1.0 的六个元数据关系共40行与实际 Rust 事实完整 multiset 相等；最终基线事实未变化，证据复用说明在 reference-evidence-reuse.json。该比较不包含 SQL 排序、opcode、HostLab 或性能资格。

## 根因

section 范围只能证明内存边界，不能证明对象起点。class_data 的物理 map 项与 class_def 所引用的真实定义也不是同一集合；未引用并不自动合法，也不自动非法。SDK37 实测允许空 orphan，以及 owner 在 class_defs 中的未引用非空 field/method item；owner 缺失的非空项、非法索引/flags/delta 则拒绝。

## 最终方案

复用共享 type_list_item_starts 校验接口列表起点；按物理 map count 有界读取全部 class_data，验证 delta、索引、组标志、body 状态及隐含 owner，并建立真实起点集。class_def 引用必须命中该集合。合法未引用项保持可接纳，只有 class_def 实际绑定的成员进入逻辑 class_fields/class_methods，物理 orphan 不静默增加真实定义。共享空项保留；共享非空、重复定义与错误布局定位诊断。

事实持有 MetadataFacts 的字节 lease；ref/def EntityKind 与 class_def_idx/type_idx 分开。单次 resolve_class 拒绝混合 snapshot。methods 的未建代码列返回 INCOMPLETE_FACTS，拼错列返回 INVALID_ARGUMENT。

## 失败方案

未采用“一律拒绝所有 orphan/nonempty orphan”的方案：SDK37 的已定义 owner 正例退出0，证明该限制会过拒绝。早期只跳过物理编码值的 native 路径实际接受了非法 orphan 索引，修复前记录仍保留。扩展 oracle 时曾把 field/method 越界统一标成 INDEX_OUT_OF_RANGE，导致诊断类别不够精确；保留失败 stderr 后细化分类，没有更改输入或用默认 skip 消除失败。并行 instructions 初次 Clippy 失败也保留，随后完整 Clippy 已通过。

## 验证范围

Windows x86_64、Rust 1.99.0；40 个独立/手工语料、5 个 reader 测试、2 个 facts 测试、Clippy -D warnings；035/037/038/039/040 定义布局均实际执行。支持字段、接口继承、虚方法、native/abstract/引用无定义、根类 NULL 与 sourcefile 孤立代理等明确语义。没有据此声称完整 ART、代码/注解、SQL profile、HostLab、Linux 或性能资格。

回滚时停用上层对新 definitions 模块的接入，保留输入、失败/成功证据与旧来源事实；不删除用户 APK、重置外部仓库或放松已有源摘要/完成门禁。
