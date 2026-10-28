# ADR-012：DEX 头完整性校验升级

状态：accepted。日期：2026-10-28。关联 MDD-013/MDD-020 的后续边界强化。

M1 的 header-v1 校验范围、Adler32 和来源 SHA-256 均已实际验证，但明确保留 `signature_verified=false`。该历史结果继续保存在原始验收和 Git 检查点中，不能追写为已经执行 SHA-1。

用户另行批准 RustCrypto `sha1` 0.11.0；依赖真实存在，MIT/Apache-2.0，精确包摘要进入 Cargo.lock。新 header-v2 对 bytes[32..file_size] 计算 SHA-1，与 bytes[12..32] 逐字节比较，失败为 INVALID_INPUT / SIGNATURE_SHA1_MISMATCH。Adler32 与 SHA-1 继续分别诊断，均不能替代 SHA-256 来源身份。这里的 DEX signature 是格式摘要，不是可信发布者的密码签名。

没有采用自己编写 SHA-1，也不借用外部命令或另一个项目的私有实现。原包用 Python hashlib 独立生成的合法/坏摘要语料继续作为对照，不改 golden 迎合实现。完整 DEX、ART、业务或性能资格仍未授予。

初次全量重新解析锁文件意外带入九项无关传递版本升级。该候选保存在 `artifacts/integration/20261028/sha1-rejected-unrelated-upgrades.lock`，不采用。恢复上一提交的精确锁文件，再以普通增量解析仅新增 sha1 一个包，保留原版本；当前锁差异只有该包和 mdd-dex 的依赖边。

升级后的验证保存于 `artifacts/integration/20261028/sha1-final-tests/` 和后续原生 CI；先前候选锁测试不用于当前锁资格。回滚时通过独立提交撤回本次依赖和 header-v2，恢复 header-v1 的未验证声明，不能在移除校验后保留 true。
