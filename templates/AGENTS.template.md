# MeguvizDexDash 工程协作约定模板

这是拟定模板，不是当前工作区的有效 AGENTS.md。实施时结合所在仓库现有规则使用，遵守正常指令优先级，不覆盖用户明确授权或既有约束。

## 范围与权威文件

产品是桌面/云端 DEX 引擎 MeguvizDexDash。通用核心不包含 HostLab/BIL 规则；DexMeguviz/DexKit 是独立项目。先读 README、ENGINEERING_PLAN、相关 docs 和 STATE；唯一任务图为 tasks/backlog.json，接口契约以 contracts 与 docs/02 为准。

## 改动方式

一项任务一组可审查变更；不清理他人的未提交修改。共享文件指定单写入者。依赖未满足时可以做独立调查、测试工具和语料，不能把未经验证的接口假设写入生产消费者。任何 API/schema/cache 破坏性变化同步版本、消费者、测试与 ADR。

## 正确性

来源快照、输入多重性、MUTF-8、引用次数、NULL/排序与指纹语义不得因性能优化改变。partial/unknown、超时、截断、丢失 End、worker crash 不能转换成空成功。fallback 只在规定条件下发生，资格测量中的必需任务不依赖旧引擎回退。

## 验证

先跑改动相关验证，再跑阶段要求。未执行写 not_run，受阻写 blocked 并附原因。构建、测试、差分与性能命令必须真实存在。运行日志/摘要/证书登记 artifacts/index.json；不得把历史 evidence 当成本实现已通过证据。

## 性能

完整 producer→consumer、完整报告与公平总资源是比较单位。固定 A0/A1/A2/B0/B1 身份；测量独占 CPU 时段，保留逐轮记录。相对最佳可部署现成路径报告新增价值；不叠加重叠成本、不把消费端微基准外推为整任务收益。

## 交接

更新 STATE、task 状态、ADR、compatibility ledger 与 artifact index。重要结论写六段经验记录：现象、证据、根因、最终方案、失败方案、验证范围。恢复时读文件，不依赖聊天记忆。远端发布/默认切换依当前会话实际授权，不从本模板推导额外授权。
