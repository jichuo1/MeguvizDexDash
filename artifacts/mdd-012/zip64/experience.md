# MDD-012：ZIP64补齐与ZIP32对齐填充回归

## 现象

原实现只完成了ZIP32原型，ZIP64仍明确不可用，但docs/04把单磁盘ZIP64列为首版必需能力，因此根重新打开012。扩展extra解析后，固定NewPipe的classic输入出现INVALID_INPUT；严格TLV遍历把Android local extra尾部的短全0对齐填充当成截断字段。

## 证据

zip32-regression/local-extra-observations.json记录293个短全0 local extra（1–3字节）。修复后同SHA公开APK实际inventory为1351成员、2个选中DEX，选中数据完全解压并触发CRC验证；命令、输出在同目录。原8个归档测试加3个ZIP64测试最终全部通过，完整input的13个单元测试和Clippy均通过；final/保留全部实际输出。

tests/fixtures/zip64/manifest.json包含52个语料：26正、26负。Python stdlib zipfile完整消费正例，按ZipInfo读取以保留同名成员。实际65535与65536成员归档跨越16位计数边界；均只有少量真实payload和空资源，不是4GB数据。超过32位的单成员尾偏移及u64溢出另以虚拟字段测试，未冒充合法大输入运行。

## 根因

ZIP64不能以u32 cast复用旧记录；EOCD64、locator、条件0x0001字段和每文件descriptor位宽需要分别验证。全归档因计数采用ZIP64，不等于每个文件descriptor都变64位；仅central offset扩展也不要求正常32位local header升级为45。另一方面，Android已存在的local零对齐填充需要保留，不能把新增严格字段验证外推到全部旧padding。

## 最终方案

所有64位计数/长度/偏移先经过预算、checked arithmetic及host范围检查。先按原始CDE ordinal枚举，再以原始数据前缀、单个CDE与合法32/64尾记录构成零复制视图，让批准的zip8.6处理STORE/DEFLATE和CRC。0x0001按sentinel条件取值，local同时包含两个尺寸；重复或截断信息、矛盾locator/尺寸/descriptor均拒绝。声明巨量与累计溢出返回QUOTA_EXCEEDED，损坏返回INVALID_INPUT；多卷、加密和其它codec保持unsupported。

local允许短全0尾padding，并以1/2/3字节正例和非零截断反例固定边界；不会吞掉截断ZIP64字段。descriptor只在已知data_end解析，支持有/无signature及CRC恰等于signature的情况，不扫描payload猜边界。

## 失败方案

新增严格TLV解析首次破坏公开classic输入；失败现象由根公开流程保留，局部观测与修复验证追加保存。未用通用ignore-extra绕过，也未放宽ZIP64所需字段长度。旧STORE损坏尺寸测试原先等待read阶段拒绝，现metadata阶段已能证明矛盾，改为更早拒绝并保留真实INVALID_INPUT。没有把所有0xffff计数当ZIP64必需：Python实际65535成员classic与65536成员ZIP64都已验证。

## 验证范围

依据PKWARE APPNOTE6.3.10相关记录规则，规范来源链接保存在manifest。Windows x86_64/Rust1.99.0已实际验证全部52向量、11个archive与13个input单元测试、Clippy；固定公开NewPipe默认路径恢复。没有运行私有APK大解析或额外私有SHA重算，没有性能结论。Linux最终源码仍由根native CI验证；不声称实测4GB数据、加密或多卷支持。

回滚可退回明确标注ZIP32原型的旧实现并撤回ZIP64 capability，保留本次失败/成功证据及所有原输入；不得放宽原始源摘要或把未消费/CRC失败当完整输入。
