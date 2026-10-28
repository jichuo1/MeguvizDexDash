# 当前可执行验证

使用 Rust 1.99.0 与 `requirements-dev.lock` 指定的独立 Python 开发环境。Windows 本地为 `.venv/Scripts/python.exe`（3.12.14）；两平台 CI 固定 Python 3.12.10。官方托管清单没有 Windows 3.12.14，首轮真实失败后选择了双方可取得的同一精确版本，环境差异明确记录。

- `python tools/verify_original_handoff.py`：从不可变初始 Git 提交重建原包并严格校验；不是引擎测试。
- `python conformance/oracles/reproduce.py`：实际生成/比较小语料、手工期望、独立编码与变形验证。
- `cargo test --locked --workspace`：运行当前实际模块测试；不替代完整格式或 HostLab gate。
- `cargo build --locked -p mdd-cli` 后运行 `python conformance/check-cli-contract.py --binary <实际二进制路径>`：检查真实能力 JSON 与未准入状态。
- `python conformance/check-workspace-boundaries.py`：检查实际依赖图没有外部业务/provider 反向依赖。
- `cargo run --locked -p mdd-build-probe`：运行真实依赖和只读虚表有限实验，输出明确保留语义差异。
- `python tools/check_progress.py`：检查唯一任务图、完成依赖/产物和证据摘要；不自行授予任何资格。

命令记录由 `tools/record_command.py` 保存 argv、目录、退出码、原始 stdout/stderr 和摘要；其耗时是开发观测，不作性能试次。大型私有 HostLab、A0/A1/A2 正式基准、完整 AOSP 格式资格按 STATE 中的具体阻塞恢复，不能以默认 skip 计算通过。
