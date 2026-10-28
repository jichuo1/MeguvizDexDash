# M1 直接 worker 监督

Supervisor 启动调用方提供的 Command，固定 stdin=null、stdout=pipe、stderr=null，只承担生命周期观察。没有查询协议、MCP、机器结果或支持列表注册；收到任意 stdout 文本不构成请求成功。

Windows 使用 PeekNamedPipe 检查可读字节；Linux 使用非阻塞 pipe。每次 poll 有固定读取上限，累计 stdout 字节预算与总期限来自 mdd-session 的 ResourceLimits。没有额外后台reader线程或无限队列。EOF、零/非零进程退出和管道错误都使未完成请求失败；stdout预算和期限保留 QUOTA_EXCEEDED / DEADLINE_EXCEEDED，不能洗成成功或 unsupported。有效完成过的请求保持终态。

监督结束会 kill/wait 直接子进程并关闭读取端。当前没有 Windows Job Object、Linux进程组/cgroup或多后代清理，不提供进程树/安全隔离资格，不能据此解锁正式性能runner或M8资源资格。未来 worker 若能启动helper，必须先加入真实进程树管理；本轮原生测试child不创建后代。Linux实现待原生Linux运行，不能以Windows测试宣称Linux通过。

测试用本 crate 的实际 Rust 测试二进制生成独立子进程，覆盖非零退出、零退出缺失终态、子进程仍存活时关闭stdout、输出预算和期限。测试中模式环境变量只供测试进程，不是对外服务接口。
