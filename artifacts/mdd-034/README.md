# MDD-034 有界运行与完整终态

本目录记录真实本地机制验收，不授予完整引擎、接口、HostLab 或性能资格。最终入口为 budget-and-terminal-states.json；`python -O conformance/runtime/qualify.py` 复核真实原始输出和命令状态。

当前实际通过：27 个 query 单元、10 个 session 单元、7 个 types 单元、2 个 compile-fail，相关三包严格 Clippy 全 target。两独立 SQLite connection 均进入 VM，A 被 interrupt 后返回 OperationInterrupted，B 得到正确和且两连接都能继续 SELECT 7；2 秒保护未触发。独立自有 child 的 250ms deadline 真实触发并回收，两个未完成 query（含计算完成但未消费 spool）均失败，原先完全交付的 query 保持完成。process_tree_isolated=false 明确保留。

预算按 global→worker→session→query 收紧，19 个资源维度分别记录累计工作与驻留 reservation。物理内存 reservation 同时计入 ResidentBytes；QueueBytes/Items 只记录排队，不重复计 payload 的物理驻留。真实 Arc 身份与 owner lease 保护共享对象；同 hash 的不同独立分配照常计费。借用必须同树且原 owner 为目标祖先，并通过资源及 resident 个体限额；不声称 borrowed 对象已形成 query 合计驻留。

捕获适配器先按文件元数据保守预留工作空间与输入驻留，再调用受硬读取界限保护的 Snapshot。归档先只读目录预检，复用 InventoryPolicy::selects，实际解压前原子预留。CRC、SourceChanged 和其他原错误不改为 unsupported。预算化 member() 持有来源及驻留 guard；旧低层 read_member 等入口仍有自身 limits，不会自动加入全局 pool。facts 闭包是受信 producer，须遵守传入的 reader limits、workspace/ready 上界与实际行数申报；这里不声称逐次 allocator/RSS 精确测量。

等待队列位置的 sender 也持有 payload 驻留 reservation；出队后返回的 Budgeted 值继续持有该 lease。取消、接收者关闭和错误释放 reservation；producer 没有明确 End 就消失属于 WorkerLost。所有 source、Session、Worker、manifest、epoch、plan、schema 和一次执行领取在执行前核验；真实并发领取只有一个成功者。

TerminalBuilder/StreamVerifier 使用既有 mdd.result.v1，不复制错误枚举。零行、coverage Partial/Unknown、计算完成但未消费、截断、分页未尽、取消和 EOF 均独立验证。MAX 计数后的错误不能被后续成功终态洗白：root-counter-before-fix 为实际失败，修复后先计算两个新值再原子提交并锁存错误。另保留跨预算树、错 session/worker、阻塞内存和输入预分配反例。fallback 只有显式等价政策下的三种许可错误，完整替代资格不允许借 fallback 通过。

预算树 owner 与 live reservation 元数据分别有 10000 的明确生命周期上限；达到上限返回 QuotaExceeded，不伪装无限常驻能力。软硬 deadline 是继承后的绝对最小时间；硬到期提供 supervisor 所需信号。完整 worker/MCP/FFI 接线、跨进程消费确认与生产入口强制执行属于后续任务，当前 CLI 不因此广告新公开能力。

原分工在两次内容检查中断后由 root 接管；中断不是工程测试结论。已完成记录、真实编译错误、原 MAX 计数红例和后续绿例全部保留。回滚采用审查分支范围 revert，不删除原工程包、失败记录或其他任务修改。
