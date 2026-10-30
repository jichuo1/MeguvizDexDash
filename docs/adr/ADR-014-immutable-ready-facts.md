# ADR-014：已验证事实只提供只读访问

状态：accepted（未发布Rust SDK的边界强化）。日期：2026-10-28。

## 问题与根因

早期MetadataFacts/DefinitionFacts/CodeFacts是携带complete与来源身份的高层对象，却暴露public可变Vec和来源字段。可信Rust调用者也可能误清空行或改来源后，把仍标complete的值交给后继构建器。源blob SHA正确并不能证明被改写后的事实仍对应该blob；这违背原架构的不可变事实契约。

## 决策

已验证高层对象字段改为crate内可见，通过只读getter提供来源、schema、事实slice、coverage及完成层。底层解码DTO与脱离对象的输出副本仍可读写，但不能被注入已验证的高层对象。私有MemberBlob持有同一不可变字节lease，构建器继续绑定来源并检查内容身份。没有暴露可变getter或从任意JSON直接建立Ready事实的入口。

外部SDK示例全部迁移到getter。序列化JSON字段保持不变，debug策略新增语义字段由ADR-013约束；本变更尚未进入正式ABI/schema发行。future worker/cache/provider仍需独立验证，不把反序列化当Ready。

## 验证与回滚

`artifacts/integration/20261028/immutable-facts-check/` 的全target检查和 `immutable-facts-doc/` 的外部compile_fail契约已实际通过；代码层同类保护由MDD-023记录。原有来源/字节/多重性和独立数据差分继续执行，禁止用私有字段变化规避运行测试。

若撤回，只能恢复未取得不可变事实资格的开发状态，不在字段重新开放后保留安全/完整性声明。与published API发生兼容变化时必须另发版本和迁移文档；当前消费者均在本项目内同步修正。
