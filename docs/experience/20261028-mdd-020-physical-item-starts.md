# MDD-020：物理条目起点不能用范围包含替代

## 现象

旧字符串读取器接受 string_id 指向 string_data 内部字节，产生看似完整的空字符串元数据。相同输入被 Android SDK 37 的 dexdump 明确拒绝。type_list、class_data、debug_info 有同类风险。

## 证据

`artifacts/integration/20261028/item-boundaries/` 保留可重复生成器、五个输入、SDK原始输出、旧native exit0与修复后exit1、定向回归与公开输入完整重建。bad-interior-string 的引用为117，真实map item起点116；SDK错误为未找到预期string_data的data-map entry。坏type_list引用140，真实起点136，SDK同样拒绝。固定AOSP verifier源码SHA为8e3d595c8c37e7e49f5df2070db9d93bc6825a6e351eadbee7e342a6a52cb207。

## 根因

section范围验证证明可读，不能证明引用指向该类物理item的起点。之前只从ID偏移解码并检查范围/重叠，未先证明map中实际variable-length item的边界。另一个旧header约束错误地要求string_data物理数量等于string_ids逻辑数量，可能误拒绝合法未引用项。

## 最终方案

字符串按map count从物理section起点有界遍历，再将有序引用匹配真实起点；保留合法未引用数据，引用仍按string_idx输出并验证UTF16严格顺序。type_list按4字节对齐完整遍历并验证索引/填充/总预算，proto及接口引用必须命中实际起点。class_data和debug_info由对应模块使用同一原则。来源SHA256与逻辑引用身份不因物理项数量不同而混同。

## 失败方案

只检查offset在section中会把内部字节误认新item。直接禁止未引用项或强制物理/逻辑count相等会过拒绝；合法orphan-string-data与unused-type-list已由实际SDK exit0确认。旧测试绿、单一解析器自比或相同行数都不能替代此边界验证。一次新增测试的模块路径编译错误及错误cargo过滤命令均原样留档。

## 验证范围

新正反例与真实SDK对照、生产读取器定向回归、原有手工MUTF/LEB/prototype语料及相同NewPipe SHA的完整metadata重建。未据此取得完整ART、HostLab或性能资格。MDD-020曾重新打开，修复通过后由新证据恢复；若撤回修复必须撤回对应完成/资格声明，不能保留旧complete。
