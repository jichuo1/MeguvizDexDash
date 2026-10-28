# 有界 Rust parser 安全检测

此目录落实 `docs/04` §9.2、G1 和 §14.2 的有限检测准备。发布 Rust **1.99.0** 保持不变；测试编译器独立锁为已实际取得官方 manifest、并对四个 Linux 组件执行 HTTP 200 检查的 **nightly-2026-10-28**（1.101.0-nightly，41089d07a）。组件 hash、crate 官方来源与 checksum 在 `toolchain-lock.json`。HTTP 可取得并不代表已经在本机安装或执行 ASan。

`fuzz/` 是独立 workspace，沿用根已验证依赖锁后新增 dev-only `libfuzzer-sys=0.4.13`、arbitrary、jobserver；独立 `Cargo.lock` 不改变根依赖。CI 安装注册表固定 `cargo-fuzz=0.13.2 --locked`。两份工具的下载内容在执行前再次比对登记的 crates.io checksum。目标只引用 Rust mdd-dex/input/types，不调用 SQLite、HostLab、网络或私有 APK。

已实际检查固定crate源码：cargo-fuzz 0.13.2 的内部cargo命令没有透传 `--locked` 开关。因此runner只为这些子进程安装临时cargo shim，给build/metadata等实际调用强制补 `--locked`、记录每条argv，并拒绝未知子命令；外层仍用真实cargo绝对路径。运行前后还核对独立锁hash。没有修改cargo-fuzz或系统安装；显式开启整数overflow checks。

| 目标 | 真正入口与不变量 | 预算/限制 |
| --- | --- | --- |
| archive | 文件 capture → ArchiveInventory，selected DEX blob content hash/lease、held source 字节不变 | 输入64KiB，128成员，目录64KiB，单成员64KiB，总展开128KiB；含ZIP32/ZIP64、stored/deflate/descriptor seed |
| mutf8_leb | 两类 LEB32 对照独立 i128 基数算术；MUTF-8 成功结果从保留 UTF16 单元独立重编码 | 64KiB；保留NUL、surrogate；非canonical拒绝回归 |
| header_raw | 完整严格 header/checksum/signature → strings/types/protos | 1024 strings、32768 UTF16单元；错误checksum保持错误 |
| header_repaired | 仅修复 file_size、SHA1、Adler32，再走相同入口 | 不修magic/map/table，保留生产校验；不能绕过其他结构失败 |
| code_payload | repaired header → 全code map、payload、handlers、debug EncodedFactsV1，成功range均在原bytes内 | 256 code、32768 units/instructions、8192 payload/targets/debug operations、2048 catch pairs |
| encoded_values | repaired header → strings/types/protos/definitions → physical annotations/encoded arrays/handles/callsite prefix | depth16、1024items、4096nodes、8192rows、256KiB解码；不冒称运行时注解类型或bootstrap已解析 |

已有 generators 只作回归种子，和生产代码可能有共同规范祖先，不能充当独立事实 oracle。`corpus-manifest.json` 逐项绑定源和字节 hash。两个约5MiB的65535/65536成员向量明确排除在64KiB smoke之外，由普通ZIP64回归负责。041、AXML、ARSC、持久reader、批协议、QueryIR、分页/cancel尚未有本配置的 fuzz 目标；TSan/MSan/其他平台和 C/C++ FFI ASan/UBSan均未验证。

本地可复现（仓库根）：

```text
python conformance/sanitizers/build_corpus.py
cargo test --manifest-path fuzz/Cargo.toml --locked --lib
cargo run --manifest-path fuzz/Cargo.toml --locked --bin mutation-smoke -- fuzz/corpus 64
cargo clippy --manifest-path fuzz/Cargo.toml --locked --lib --bin mutation-smoke -- -D warnings
```

Windows 本地 stable smoke 没有 sanitizer 或覆盖插桩。Rust assert 不会被 release 优化删除；panic 不捕获，InternalFault/越界不变量失败直接令进程非零。普通 malformed-input Result 是拒绝计数，不能计作解析完成。archive 经生产 capture 的输入 magic 拒绝也必须作为正常拒绝；首轮驱动错误日志保留于 `artifacts/conformance/parser-safety/local-smoke-1`，修复后第二轮实际通过。它不是生产修复。

Linux CI 的可复现命令：

```text
python conformance/sanitizers/run_ci.py --verify-only
rustup toolchain install nightly-2026-10-28 --profile minimal --component rust-src
cargo +nightly-2026-10-28 install cargo-fuzz --version 0.13.2 --locked
python conformance/sanitizers/run_ci.py --output artifacts/conformance/parser-safety/ci --seconds 15
```

`run_ci.py` 先验证锁和全部种子，再以 `-Zsanitizer=address -Zbuild-std --target x86_64-unknown-linux-gnu` 编译正控制、测试和mutation。故意越界的独立 `asan-detection-control` 必须真正产生 ASan heap-buffer-overflow 和非零退出，才能验证检测器配置；它不进入产品或普通目标。随后6个 libFuzzer 目标各15秒，同样显式传入 `--build-std`，固定seed617349..617354、max_len65536、单输入timeout3秒、RSS1024MiB、硬命令超时600秒。任何非零/超时/崩溃文件/缺失真实执行和cov计数都会失败；正控制的预期错误单独标记，不算解析器crash。

CI 在私有进度库 `codex/**` 分支 push、相关PR及手工dispatch运行，无cron。工作流只授read权限，不运行业务、不上传私有输入。普通“0 crash”仅说明这个预算内没有发现，不是格式完备、UB证明、G1或MDD-026通过。原始stderr中的libFuzzer `cov/ft`是插桩计数，报告不转换成源码覆盖百分比；本地计数不是覆盖率。没有runner/工具/网络时明确失败或blocked，不能skip。

Linux 首次真实结果已回读：检查点 b29933d，run 40692557250，六目标合计 2,426,570 次执行；ASan 正控制实际产生预期非零 heap-buffer-overflow，普通目标无超时或 crash artifact。原始 ZIP 已核对 GitHub SHA-256，保存在 artifacts/conformance/parser-safety/ci-40692557250.zip。`python -O conformance/sanitizers/verify_ci_artifact.py` 独立复核全部流摘要、实际计数和 12 条子 Cargo 锁参数；摘要在 ci-readback.json。源码覆盖百分比仍未知，不授予完整 G1、026、业务或性能资格。

新增文件和独立构建产物可用范围 revert 回滚；发布工具链、旧CI与旧原始trial保持原身份。保留实际失败与成功证据。

官方依据：[Rust sanitizer](https://doc.rust-lang.org/unstable-book/compiler-flags/sanitizer.html)、[Rust Fuzz setup](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html)、[cargo-fuzz features](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html)、[libFuzzer limits](https://llvm.org/docs/LibFuzzer.html)。这些资料分别支撑 nightly/ASan、目标结构、feature传递、有限预算；不支撑本项目未运行配置的通过声明。
