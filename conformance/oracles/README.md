# 独立 fixture oracle 与验证边界

运行 `python conformance/oracles/reproduce.py`，使用实际 Python 解释器。它连续两次生成语料、逐文件比较 SHA256、验证手工期望，再执行有限的变形检查；非成功状态返回非零退出码。真实命令、输出、解释器和源摘要位于 `artifacts/mdd-004/fixture-reproducibility.json`，逐项结果位于 `artifacts/mdd-004/oracle-checks.json`。

`tests/fixtures/generate.py` 只写入 `tests/fixtures/generated/` 和自身 manifest；它不修改 `expected-results.json`。期望表由人工按布局、DEX 指令格式和 UTF-16 code units 独立列出，检查器不导入生成器或任何 Rust 生产模块。生成器和检查器都使用 Python 标准库 `struct/hashlib/zlib`，这些是共同的通用编解码/摘要基础，不是共同的 DEX reader。ZIP 的生成和检查均使用 Python `zipfile`，存在共同 ZIP 实现祖先，故 ZIP 检查只用于清单/CRC/字节期望；后继生产 Rust ZIP 库与 Python 结果的差分才构成独立实现比较。

格式参照为 [AOSP DEX 规范](https://source.android.com/docs/core/runtime/dex-format) 和工程包固定的 `platform/art@6484611fd45e69db9f33f98bfd6864014b030ecf` 身份。此处没有声称已运行该 revision 的 verifier。最小 DEX 有 112 字节头和 28 字节 map，所有表为空；它仅能证明所请求的 header/map 范围为空。`structured-035.dex` 包含 7 个字符串、3 个类型、1 个原型、4 个方法引用及定义、1 个类、两个独立调用站点、一个 native 无 body 方法、三个 code_item 和一个 catch-all。生成器同时计算 DEX SHA-1 signature、Adler32 checksum 与外部 SHA256；三者含义不同。

`strings-mutf8-035.dex` 和组件向量覆盖 encoded NUL、BMP、代理对、孤立高/低代理、坏 continuation、UTF-8 四字节形式、长度不符和缺失终止符。无损结果使用整数 code units；不进行 replacement、normalization 或 UTF-8 有损转换。LEB32 向量有最大值、带符号上下界、溢出与截断；测试 profile 为有界 permissive LEB32，允许非最短 `80 00`，这尚未宣称等同某版 DexSQL 行为。

payload 向量分别覆盖 packed/sparse switch 和 array-data 的长度、key、元素、目标字节；它们是组件向量，不是完整、经过 ART 类型验证的方法。try/catch 的完整 code_item 位于 structured DEX，检查 handler 相对偏移、区间及原始字节。未将 invoke-custom、polymorphic、完整 annotations/debug、041 共享容器或所有恶意 ZIP64 声称为覆盖。

036/041 fixture 只是 magic 拒绝测试：没有按照其格式构造合法内容，不能拿拒绝这些向量证明对所有该版本输入的全面检测。AXML 语料仅有 `manifest` 根元素和合法 chunk 布局；尚未由 AAPT2 验证资源语义。APK 后缀文件是静态分析容器，没有签名或可安装应用声明。

变形 runner 实际执行确定性生成、stored/deflate 字节等价、逻辑重复、输入次序、成员重命名、同大小同 mtime 的内容变化，以及 `class-reorder-before.dex` / `class-reorder-after.dex` 的 DEX 表与数据布局重排。后者包含两个独立继承外部 Object 的类；交换 class_def_idx，反转 string_data/class_data 布局并重写全部对应 offset。独立检查器逐项解析 string/type/proto/method/class-data 引用、核对方法 owner 与 native 无 body 语义，比较完整小 fixture 的规范化类/方法值；文件摘要、class_def 身份和数据 offset 确实不同。DEX string/type/proto/field/method ID 表有强制排序规则，不能为制造重排随意交换这些表。class_defs 在满足父类/接口拓扑约束时允许独立类交换次序，依据官方 DEX File layout。此检查验证测试输入与手工关系；快照隔离、查询分页、旧句柄、取消和 worker 丢失需要后继生产实现测试，不能把本 runner 当作这些实现的通过证据。

LEB 独立复核另保存 `artifacts/mdd-004/encoding-independent-review.json`：位移累加与反向 base-128 Horner 两种算法，对所有 128 种第五终止字节、两种低 28 位边界、signed/unsigned 共 512 项条件逐一裁决。32 位 ULEB 第五 payload 仅允许 0..15；SLEB 第五 payload 仅允许 0..7 或 120..127，否则无法在 32 位中正确符号扩展。额外手工值包含 -128/-65/-64、63/64、int32 上下界及邻值、合法负数非最短形式、六字节溢出。MUTF-8 另以 Python UTF-8 `surrogatepass` codec 独立复核；单独翻译 C0 80、拒绝四字节 UTF-8，并保持 UTF-16 surrogate units。UTF-8 codec 与手写 reader 对负向量的错误必须一致。

外部 full-format oracle（固定 AOSP dexdump/verifier、独立 dexlib2）与 AAPT2 未运行，生产差分和 fuzz 未运行；相应资格保持未获得。后继任务可使用当前 fixture 开始实现并做独立比较，完整格式或 HostLab 资格仍须执行对应 gate。MDD-004 的产物提供可执行种子、手工期望和后续验证方案，不代表整个 M2 格式实现完成。
