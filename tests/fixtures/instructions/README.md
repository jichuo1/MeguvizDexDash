# 指令与代码布局语料

`generate.py` 用 Python 标准库生成 code_item/DEX 输入，重新计算 SHA-1 signature 与 Adler32；这些是合成格式语料，不是可安装 APK。`manifest.json` 固定输入摘要，连续生成必须逐字节一致。

`generated/all-opcodes.json` 有 224 个有效 opcode、26 种格式的实际向量，另有 32 个保留 opcode 的拒绝测试。opcode 描述和这些宽度向量共用固定 AOSP 表祖先，不能因此算两个独立 oracle。`manual-expectations.json` 另列手工寄存器顺序、符号/宽值、range、polymorphic 双引用和 custom call-site 期望。

独立 `oracle.py` 不导入 Rust 或生成 opcode 表，以不同语言的 struct/LEB 读取及明确手工值检验完整 DEX 小语料的 raw code/insns、payload、catch、debug。普通与 `python -O` 均不关闭门禁；`expected-results.json` 由此独立程序冻结，Rust 逐值比较，不从被测实现生成 golden。

默认 `mdd-debug-encoded-v1` 保留完整物理 debug 程序及 `encoded_line_decimal` 原值，包含真实 Android 输入的 line0。`source_line` 仅表示普通程序中可用的正数行候选；0/负值、PC-to-PC 模式与不可用方法上下文保持 NULL、`source_line_usable=false` 和明确原因，不能把它们改成1或删除事件。`source_positions_built=false` 表示源码位置语义尚未取得完整资格。

PC-to-PC 用例保留同一物理程序被短、长 code 引用的全部事件；每事件标记相对 referring code 的 inside/end/beyond。`method_positions()` 提供全部适用编码位置的借用视图，`usable_source_positions()` 是显式正数源码行候选视图；二者均不截短原始程序。`pc_to_pc_pattern` 是编码形状事实，不能证明生产者是 R8。

显式 `mdd-debug-source-lines-strict-v1` 对未知源码行、PC模式待映射或不可用上下文返回 INCOMPLETE_FACTS，同时注明当前encoded程序已完整解析。原语料名为 `bad-debug-*` 的3个非正line与非匹配共享suffix，是严格源语义的负例，默认encoded读取仍须完整保存。预期在manifest中按策略分别登记。opcode/宽度、参数计数、register/index、ULEB/SLEB、PC与signed-line算术溢出、缺失终止和预算仍是硬失败，不能用策略改变掩盖。

完整复现使用仓库的真实命令记录器：

```powershell
& 'C:\Users\Administrator\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' artifacts/mdd-023/verify.py
```

每次产生新的 validation 目录；失败原始日志保留。该命令验证当前组件范围，不签发 HostLab、完整 ART 或性能资格。Linux 原生验证由对应 runner 单独记录。
