# EXP：超大原始对照输出的无损交接

- 任务/平台：MDD-025，Windows；结论 validated，2026-10-28，root

## 1. 现象

事实检查点首次推送被 GitHub GH001 拒收。固定 A0 文本表输出 150,527,195 字节（143.55 MiB），超过单文件 100 MiB 上限；远端分支未改变。

## 2. 证据

artifacts/integration/20261028/push-e024eca-rejected.json 保留实际失败的转录；原提交由本地 archive/m2-unpublished-e024eca 保留。原输出 SHA-256 为 5fa4e57ba3e614f852dd2db51884095af3c247647f9bfd278d3ae18a2f8225b0。

## 3. 根因

参考工具按表格对长方法 descriptor 填充，原始逐行记录体积超过远端 Git 对象限制。不是解析失败或引擎性能结论。

## 4. 最终方案

tools/archive_evidence.py 使用空 filename、mtime=0 的 gzip，流式压缩并解压重新核验完整长度和 SHA；原文件留在本地，Git 保存 archive JSON 与 1,662,643 字节 gzip。仅整理从未发布的提交，正常推审查分支成功为 b29933d，不强推或改写已发布历史。qualify_raw_evidence.py 逐字节验证存档。

## 5. 失败方案

直接推原始 143.55 MiB 对象实际失败，原始失败保留。没有通过截断、只留摘要或丢弃失败日志规避体积限制。首次在活动工作树重算资格时检测到后续 mdd-query 改变 Cargo.lock，验证器如实失败；随后在精确暂存检查点重算，不篡改冻结来源摘要。

## 6. 验证范围

该存档完整保留一次实际 stdout，不证明全部查询/审计或性能通过。恢复时可用 Python gzip 读取，按 archive JSON 核验长度和 SHA。回滚可从本地保留分支查看原提交；不要将含超大对象的分支推到远端。磁盘原件未删除。
