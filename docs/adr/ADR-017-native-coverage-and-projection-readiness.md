# ADR-017：原生事实覆盖与兼容关系装配分别验收

- 状态：accepted（设计区分保留；2026-10-29 验收结论更正），2026-10-28，MDD-026，root
- 继承：ADR-003 结果契约、ADR-014 只读事实；不提升产品 profile

## 背景与约束

已验证的原生定义、指令、编码值和字节范围能够提供全部必需原子，但不等于所有旧 SQL 列已完成装配。例如方法 opcode 原子已存在，MDD-021 的窄 Methods 接口仍正确拒绝 opcode 投影；参数编码 slots 完整也不证明 prototype 的所有位置。

## 决策

CoverageLedger 以封闭的 SelectedScope 和同源 FactView 重算 input/facts 三态，输入出现次数与 DEX occurrence 不去重。显式选定子集可以完成该子集，但报告必须保留 covers_all_captured_sources=false 及所选 occurrence 清单，负结果不外推到未选来源或运行时类路径。

ColumnDomain::NativeAtoms 证明可由已验证原子无损得到要求的字段；FrozenProjection 还要求现成关系装配与精确列门禁。17 必需关系、156 列保持原分母，当前 69 列 FrozenProjection 未装配，必须按列阻断，不能填 NULL、零或近似值。

CodeProjection、AllPhysicalCode、MethodBindings、AllMethodBodies、PrototypeParameterPositions 和 SourcePositions 是不同要求。默认编码 debug 不推成源码位置；合法短 parameter list 的位置 Unknown 不被总注解 complete 覆盖。

Partial 优先 Unknown。所有必需 producer 的实际非 fallback 错误优先于缺层或三种 fallback 错误；同一项第二个失败终态被拒绝，不能后写 unsupported 覆盖损坏。新 retry 在新审计 attempt/ledger 中明确实施。LazyIndex 原等待者始终获取原 attempt 终态，即使之后 retry 已 Ready。

## 候选与取舍

单个 facts_ready bool 无法表达这些差别。将兼容 formatter 当全部原子不存在也会错误拖延独立事实任务；反过来用 native complete 签 SQL 资格同样不成立。采用类型化请求域和细分层，保留兼容缺口，由 MDD-032/035 继续验收。

## 验证与退出条件

2026-10-29 独立复核更正：下述测试只证明各自实际覆盖的范围，矩阵中原子可用性的声明本身不能证明156列均已满足原始逐字段验收。`dex_files.file_id` 已有原生分配代码，但尚缺固定旧实现及全部来源场景的端到端逐列验证；43项完整关系比较未覆盖17关系的全部字段。MDD-026 已重新打开；原始验收保持不变，须补足逐列独立证据后重新评定。历史资格文件保留为当时的限定检查记录，不构成任务完成证明。

35 个 facts 单元与 4 个 compile-fail、219 个 UTF-16 请求及独立 Python oracle、55 个残余过滤反例、并发首次建立/重试/错误保留均实际通过。独立跨层验证覆盖 8 场景、9 DEX、331 个 target 和 43 个完整关系。根在当前共享接线另验 11 项索引/coverage 测试，冻结源码与独立矩阵一致。

字节预算为明确的结构成本计费，不表示操作系统 RSS 硬上限。查询级预算与取消由 MDD-034 接入，Linux 当前索引源码仍需其不可变 CI 结果，不从旧 CI 推断。

## 迁移、回滚与证据

不变更现有 HostLab 默认 backend 或业务规则。回滚采用范围 revert，保留真实失败、独立矩阵和原始工程包。完整证据入口：conformance/manifests/hostlab-fact-qualification.json、artifacts/mdd-026/facts-differential.json、artifacts/mdd-026/indexes/README.md。所有产品、SQL、HostLab 与性能 profile 仍未准入。
