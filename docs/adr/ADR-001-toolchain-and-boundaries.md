# ADR-001：工具链与独立核心边界

状态：accepted（本机 Windows 构建范围）；Linux 原生运行待 CI 验证。

日期：2026-10-28，Asia/Shanghai。

采用 Rust 1.99.0、edition 2024、MSRV 1.99。实际 `rustc -Vv`、Cargo、平台与命令证据保存在 `artifacts/bootstrap/20261028/`。工具链精确固定，不使用浮动 stable。

M0 的 `mdd-build-probe` 是真实依赖/API 实验包，不是引擎或 M1 已完成声明。workspace 后续只增加有实际职责的模块；依赖方向为类型/输入→DEX→事实→查询→会话→入口，HostLab 业务仅存在于 `integrations/hostlab/`。默认构建不访问 DexMeguviz，也不要求 DexSQL。

用户已在会话批准 serde 1.0.229、serde_json 1.0.151、sha2 0.11.0、zip 8.6.0、rusqlite 0.40.2、getrandom 0.4.3。直接依赖使用精确版本，传递依赖由 Cargo.lock 固定，构建使用 `--locked --offline`。ZIP 关闭默认算法集合，只启用 DEFLATE 的 Rust 实现；SQLite 固定捆绑源码，不启用 rusqlite 的扩展装载 API。实测 C 库仍包含 ENABLE_LOAD_EXTENSION 编译选项，后续生产桥必须另以 authorizer/defensive 策略关闭未承诺入口，不能把 Rust feature 关闭说成 C 层编译删除。具体依赖许可表达式和 features 记录在依赖 manifest；发布时仍需完整 notices，项目自身分发许可证尚未选择。

第一轮 Windows 原生构建验证 JSON 的十进制 u64/UTF-16 code units/NULL、SHA-256 已知向量、ZIP DEFLATE 往返和系统随机数。SQL 只读虚表由 ADR-002 单独约束；这些探针不提供 HostLab 资格。

备选是等待共享 provider 或完整自写 SQL/压缩器；不采用，因为当前工作没有这些前置依赖。Python 仅承担独立 fixture/oracle、验证与开发工具，不读取 Rust 私有布局。

发现 sha2 0.11 输出不实现旧式 LowerHex 后，采用逐字节十六进制编码并重跑已知向量；未降级或增加额外依赖。首次网络受限的开发 validator 安装失败保留为环境问题，随后在独立 `.venv` 成功安装并记录精确版本。

回滚：保持原始规格提交 `3bbf108` 和 `handoff/original/MeguvizDexDash` 不变；通过新提交撤销候选实现，不重置或清理其他工程。没有修改生产后端或部署。
