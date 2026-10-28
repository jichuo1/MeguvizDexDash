# ADR-015：原始指纹与 Manifest 共用不可变字节

- 状态：accepted
- 日期、作者、关联任务：2026-10-28，root，MDD-025
- 替代 ADR：无；沿用 ADR-014 的只读事实边界
- 范围：原始方法 insns、物理资源成员、HostLab 必需 Manifest 事实；Windows 本地验收，跨平台按不可变 CI checkout 单独登记

## 背景与约束

方法字节相同不等于运行语义相同。无 body、空 insns、资源原字节与重排 XML 也不同。指纹必须回溯同一快照、逻辑 DEX 出现、定义和物理成员，不能将不同代次事实混合。Manifest 的资源 UTF-8/UTF-16 字符串规则独立于 DEX MUTF-8。

## 决策

RawCodeEvidence 从只读 DefinitionFacts 和 CodeFacts 联合建立，逐项核验 snapshot、DEX occurrence、content identity、实际 code_item 起点及 insns_size×2 区间。物理合法但未投影的 body 为 IncompleteFacts；内部非 item 起点为 InvalidInput。Native/abstract 返回 None，合法空 insns 返回 Some(empty) 和空字节摘要。

通用核心只提供显式有序的 prefix/body 摘要 recipe。HostLab 的方法名/原型排序、类聚合选择及资源名字选择由上层 example/conformance/后续适配器实施，不进入核心。

ResourceByteEvidence 绑定快照和物理成员，读取原始解压字节并校验 CRC。ManifestByteEvidence 要求唯一 AndroidManifest.xml，资源与解析器共用同一 Arc；缺失与重复分别报 PartialInput 和 AmbiguousEntity。解析保留命名空间、typed rawbits、NULL/缺失/空字符串、未知资源引用、UTF-16 code units 和显式前缀歧义，不推导 Android 运行时默认值。

文本 XML 使用已获批准并精确锁定的 quick-xml 0.42.0，无默认特性；禁 DTD/外部实体，设字节、深度、节点、属性、事件与文本预算。AXML 使用受限读取，未知 chunk/version 明确拒绝，坏结构不返回空树。

## 候选与取舍

直接对 Smali/重排 XML 作 hash 无法保留原始字节契约，因此不作为原始证据。原生核心不内嵌旧 HostLab 的业务排序；完整公开样本已独立执行旧规则 recipe 验证。完整 ARSC/config/overlay、XML 渲染与 MCP 分页由各自任务验收。

## 验证与退出条件

4 个原始证据关键测试、76 Manifest 向量、9 个 AAPT2 小树与公开完整树、固定 A0 六页 Manifest 结果实际通过。公开 55,763 个方法、8,540 个类 recipe、792 个资源独立一致。源捕获后改写/重命名、释放原 owner 的测试通过。真实失败与格式修复记录保留。

## 迁移与兼容

本决策不授予任何兼容 profile 或默认后端切换。回滚采用范围 revert 提交，保留原始工程包和失败证据。源 SHA、schema、parser 和 policy 身份均需进入未来缓存键；不能仅凭 raw body hash 复用查询或业务结论。

## 证据

- artifacts/mdd-025/raw-evidence-conformance.json
- artifacts/mdd-025/manifest/qualification.json
- artifacts/mdd-025/raw-fingerprints/independent-public/comparison.json
- artifacts/mdd-025/raw-fingerprints/legacy-class-recipes/comparison.json
- artifacts/mdd-025/raw-fingerprints/final-public/record.json
- conformance/resources/hostlab-required.json
