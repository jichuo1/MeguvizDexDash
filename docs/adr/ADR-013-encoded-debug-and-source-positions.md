# ADR-013：完整编码debug与有效源码位置分层

状态：accepted（编码事实策略），源码映射资格未取得。日期：2026-10-28。

## 现象与实际证据

固定SHA的NewPipe 0.28.6在全物理code-map构建中三次暴露过严假设，原始失败分别保存在 `artifacts/mdd-023/public-newpipe-code-layout/`、`public-newpipe-code-layout-after-debug/`、`public-newpipe-code-layout-pc2pc/`。

classes.dex 的debug 6178493被10497个code引用，方法长度1..5036，物理程序位置PC0..23；3-code-unit方法仍可引用该共享程序。原字节为01000e1e...，与固定R8 PC-to-PC模型匹配。匹配只证明编码形状，不证明生产者身份。classes2.dex另有普通事件程序26→30→0→32，在PC18真实发出line0；原字节、解释及参考记录均单独保留。

## 决策

默认策略 `mdd-debug-encoded-v1` 只承诺完整解码实际物理程序。保留每个事件的原始范围、opcode、code-unit PC和十进制原始line，不丢弃共享程序尾部。源码line使用独立Option与usable/kind；PC-to-PC替代值、非正line、不适用当前方法的位置不能变成有效源码行。method_positions()是明确的借用投影，不冒充物理程序被截断后的完整事实。

显式严格策略 `mdd-debug-source-lines-strict-v1` 在无法提供有效源码语义时返回 INCOMPLETE_FACTS，并记录已完成的编码层。它不把line0改成1，不把真实格式错误包装unsupported，也不把整个合法编码程序说成损坏。raw/source策略和版本进入scope与未来缓存键。

字节/section/item起点、ULEB/SLEB、寄存器、索引、终止、算术表示与实际物化预算继续严格校验。非法opcode、截断和越界结构仍失败。普通source事件与共享程序相对方法的上下文标签明确保留，绝不授予ART数据流、Java源码或运行期映射资格。

## 验证与范围

独立手工/SDK/原始R8模型、双策略正反例及Python独立oracle均在 `artifacts/mdd-023/`。最后一次公开输入运行 `public-newpipe-code-layout-encoded-policy/` 实际exit0，完整消费两个DEX全部52332个code item、1057648条指令和全部物化debug事件。摘要单列没有可用source line的事件，source_positions_built/full_audit_complete仍false。

## 失败方案与回滚

把debug PC当指令边界、把共享程序限制为当前短方法长度、把所有非正line认定字节损坏都会误拒实际APK。直接跳过debug或伪造line1会损坏证据，不采用。回滚需同时撤回对应策略与完成声明；保留原始输入、失败、策略版本和消费者迁移，不改变事实/完整定义去迎合旧测试。
