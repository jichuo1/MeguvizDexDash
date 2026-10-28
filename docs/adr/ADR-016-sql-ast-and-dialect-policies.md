# ADR-016：固定 SQL AST 解析依赖并分离方言政策

- 状态：accepted（依赖与实现边界）；SQL/profile 资格仍未准入
- 日期/任务：2026-10-28，root，MDD-031
- 继承：ADR-002，不替代固定 SQLite 只读虚表路线

## 背景与约束

SQLite 的默认 TEXT、CAST、LIKE、长度与排序不能直接代表新引擎或旧 DexSQL 的文本契约。M0 已有五类具体反例。结构化修改表达式需要真实 AST，不采用 SQL 字符串或正则替换。SQLite 的公开 prepare 接口不提供可改写 AST；重写完整 SQL 数据库也不作为起点。

## 决策

用户已明确批准 sqlparser=0.63.0（Apache-2.0、关闭默认特性、仅 std）及 log=0.4.34（MIT OR Apache-2.0）。独立探针实际取得并构建两个固定包，验证 CAST/LIKE/ESCAPE AST 往返；根锁仅增加这两包，其他外部版本不变。生产依赖、features、checksum 与许可证由实际 cargo metadata 登记。

桥使用真实 AST 绑定与类型传播，再生成参数化表达式；不根据不完整 source spans 做文本手术。parser、token、结构复杂度、AST walk 和 formatter/drop 的深度均须受限，关闭可选递归保护不等于已获安全资格。合法但未实现语法与真实语法/绑定错误分别记录，不将实际输入或内部错误包装为 unsupported。

原生 SQL、DexSQL 0.1.0 和 0.1.1 为不同政策。现有 MDD-030 的原生 UTF-16 token LIKE 与 SQL 文本的 LIKE/ESCAPE 也分开，不从某一政策的测试反推其他政策。输出值保留精确 64 位十进制、F64 原位模式、UTF-16 和独立原始字节；内部 SQLite carrier 不能被用户 BLOB literal 冒认。

只读 provider/cursor 持有自己的 Arc 与行坐标，不建立自引用借用，不以每 next 重新 scan.nth 制造平方成本。首轮 full scan，不启用 omit、orderByConsumed、LIMIT/OFFSET 或 IN 下推。required relations/layers 在执行前按绑定计划验证，优化掉扫描不能洗白缺层。

## 候选与取舍

仅增加 UDF/collation 无法处理 CAST、CASE、literal、连接与类型传播，不能作为全部语义适配。sqlparser 仍有方言和 source span 缺口，需要独立 binder/emitter 与明确资格；它是语法前端，不是 DexSQL 的源码恢复。完整事实 ETL 与重写通用数据库不进入默认路径。

## 验证与退出条件

先实际检查只读 vtab、authorizer、defensive、扩展关闭、generation、预算与取消；再用冻结 corpus 和精确旧二进制验证 NULL、长度、CAST/hex、LIKE/ESCAPE、比较、聚合、排序、JOIN/CTE。任何必需语义未通过继续阻断相应 profile，不能只以默认 SQLite 相等或拒绝必需输入缩小分母。

## 迁移与回滚

SQL 桥仍为候选库入口，不切换现有 HostLab 默认配置，不合并或发布。TEMP 与 catalog 代次由 MDD-033 管理。回滚采用审查分支范围 revert，保留依赖来源与失败记录，原始事实层无需改用旧引擎。

## 证据

- artifacts/mdd-031/dependency-preflight/identities.json 和 record.json
- artifacts/mdd-031/a0-literals/observations.json：固定 A0 的真实微量语义观察，不能泛化到其他方言
- docs/adr/ADR-002-sql-bridge.md
- https://github.com/apache/datafusion-sqlparser-rs/blob/v0.63.0/Cargo.toml
