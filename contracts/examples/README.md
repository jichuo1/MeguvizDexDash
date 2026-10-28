# 协议形状示例

本目录全部为人工构造的 **example fixture**，只演示拟定协议的形状；不是 MeguvizDexDash 实际执行结果，不是实现进度或兼容证据。example ID、空摘要与 0.0.0-example 版本都不得作为生产身份。

- result_complete.example.json：假设某个明确 scope 的查询完整返回零行。
- result_page.example.json：假设计算已经完成，但还有输出页，完整消费尚未完成。
- result_error.example.json：假设某个输入成员失败，不能当作完整零行。
- capabilities_unqualified.example.json：未准入的设计示例，所有列出能力均不可用。

没有提供虚构的 benchmark-run 成绩示例；实际实现后依据 schema 写入真实观测。
