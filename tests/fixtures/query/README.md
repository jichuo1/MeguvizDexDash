# Typed query v1 手工关系语义

`build_cases.py` 固定输入表和人工期望，独立 Python 全物化 oracle 用普通列表、整数、集合和稳定排序复核26项正例；10项负例由 Rust 真实执行其错误阶段与原因。它不导入生产代码、不调用SQL或DEX工具。`cases.json` 的重复行、NULL、空bytes、含NUL文本、孤立代理、跨DEX相同local index均有独立身份。

`like_oracle.py` 另有20项人工期望，以“可消费前缀长度集合”独立验证原生UTF16 pattern。Rust主路径是DP，参考路径是受预算递归；`%`、`_` 和显式单code-unit escape仅是 `mdd-text-v1` 的原生pattern记法，不代表SQLite/DexSQL SQL方言已准入。NUL不终止文本；孤立代理占1个code unit，补充字符代理对占2个；未指定escape时反斜线是普通字面量；尾部显式escape真实拒绝。

`codec_oracle.py` 使用Python标准库Base64及canonical重编码，产生322项正例（0..65字节长度及所有单字节值）和12项拒绝。Python的validate=True本身不拒绝全部非零padding bits，因此人工策略另要求重编码完全相同。

所有脚本在 `python -O` 下仍验证；必要门禁使用显式异常。JSON固定LF，不随Windows换行变化。共享generator祖先与独立oracle身份应区分：小表期望由人工给定，Python只复核；它们不是完整DEX或SQL oracle。
