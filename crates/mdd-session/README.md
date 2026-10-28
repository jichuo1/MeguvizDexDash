# M1 生命周期注册表

本 crate 实现生命周期对象与资源预留，不执行 SQL/typed 查询，不注册虚构行结果或任何已准入 profile。

Lifecycle 可通过 Arc/Mutex 安全共享。快照、session、query、cursor 是不同 Rust 类型，运行时还检查随机 runtime owner、对象 identity、generation 与父对象。原始句柄不可自行反序列化；release 后旧 ID 被拒绝。有效 handle 的 close 可幂等，release 不是幂等。

Snapshot 注册表与 session/query 各持有 Arc<Snapshot>。close_snapshot 只关闭新 session 接纳；release_snapshot 删除注册记录，已有 lease 保留同一字节。close_session 只取消所属未完成 query 并关闭其 cursor；其他 session 不受影响。原生 catalog epoch 在 prepare 时固定，后续目录代次不替换旧 cursor 的绑定。

QueryPhase 区分 prepared/queued/active 与 completed/cancelled/failed。complete_execution 释放计算线程预留并保留 active 交付阶段；finish_cursor 确认对应结果已消费。close/release 未消费的 cursor 会永久标记该查询交付被放弃，不能靠删除 cursor 再 finish_delivery 获得成功。finish_delivery 只在计算完成且全部 cursor 已消费后完成。计算后取消保留 execution_complete=true。此处的消费确认由未来实际算子/结果消费者驱动；当前不证明任何 DEX 查询完成。

ResourceLimits 在 runtime/session/query 取更严格适用额度；线程预留、query/cursor/session 句柄数、缓冲字节预留和总期限都经过检查。零表示零额度。线程额度约束计算预留，未宣称是操作系统线程上限；缓冲是调用方必须取得的逻辑预留，不是通用 allocator 或内核 RSS 限制。未实现内存硬限、持久spool和M4批所有权，能力发布时须继续 unavailable。

每个 Lifecycle 对应一个 worker 作用域，同一时刻只有一个 supervision lease。worker loss 将所有未完成请求一次性标记失败，已完成终态保持；其他 Lifecycle 不受影响。失效 runtime 不自动重开或复用旧 session/cursor。
