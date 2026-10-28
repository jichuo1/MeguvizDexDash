# EXP：私有 Manifest 完整树、显示别名与交付终态

- 任务/平台：MDD-025 后续授权输入验证，Windows，2026-10-28，root
- 结论：validated；不授予完整业务或性能资格

## 1. 现象

两个固定授权 APK 的原生 Manifest 完整 JSON 为约 4.6 MB，超过首次驱动的 4 MiB 日志上限，被监督器以 log_quota 中止。原始输出虽含 calculation_complete=true，驱动仍保留失败。上调为明确的 32 MiB 开发日志上限后，两个 producer 都正常退出且进程树清空；完整树比较随后发现浮点显示和零引用显示的两处差异。

## 2. 证据

- artifacts/integration/20261028/private-manifest-20261028T133056247555Z.json：首轮 quota 失败，驱动副本为 private-manifest-first-driver.py。
- private-manifest-20261028T133340493679Z.json：完整 producer 成功，初始显示比较失败。
- private-manifest-20261028T133711100506Z.json：完整 producer 再次成功，严格比较定位零引用的显示别名。
- private-manifest-captured-conformance.json：完整原始输出 hash、二进制与输入身份均复核后的最终离线 consumer 结果。

原始私有输出与 traceback 在各 receipt 指定的 artifacts/local 目录，不进入远端。所有失败记录保留。

## 3. 根因

第一处为比较器把 float32 生成为固定六位小数，而 AAPT2 使用较短显示；2.4 与 2.400000 不同文本不说明原位模式不同。第二处为 AAPT2 把 TYPE_REFERENCE/data=0 显示为 @null，而原生保留其引用类型。不能因此把它改成 TYPE_NULL。

## 4. 最终方案

新比较器对 AAPT2 的浮点十进制重新编码为 float32，要求与原始 bits 完全相等，不用 epsilon。零引用仅在 AAPT 显示投影中对应 @null，原生类型保持不变。独立 Python AXML walker 对每项属性核验 data_type、raw_data 和 rawValue 索引，再逐节点比较 namespace/name/parent 与有序属性，不跳过差异。

最终 consumer 只复用 status=completed、tree_empty=true 且 stdout 摘要一致的 capture；不复用首轮被杀进程的输出。它重新核验当前授权输入完整 SHA 和两份 producer 二进制身份。没有改生产 Manifest 解析器或旧 frozen oracle。

## 5. 失败方案

4 MiB 日志上限实际不足，交付中止不能按 producer 自报完成洗白。原先按显示字符串严格比较浮点、直接显示资源零引用为 @0x00000000，均在两个真实样本中失败。它们是比较器的表示边界，不是放宽原始事实校验的理由。

## 6. 验证范围

9161100：2,115 节点、5,275 属性；9170100：2,119 节点、5,291 属性，所有属性原位模式和完整树通过。各含一个浮点精确检查、一个零引用显示别名、20 个 AAPT 省略空 rawValue 的显示情形。两项伪造 raw_data 位模式反例均拒绝。该结果不含 ARSC、运行时默认值、完整 HostLab 报告、MCP 分页或性能试次。回滚只撤回新比较器与驱动，保留全部原始 evidence。
