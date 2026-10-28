# MDD-012：ZIP 同名中央目录成员被上游名字索引折叠

## 现象

直接用 zip 8.6.0 的 ZipArchive::len/by_index 遍历 duplicate-name.apk 时，只能看到 1 项；独立 Python ZipInfo 清点与人工 fixture 实际包含 2 个同名中央目录记录，且内容不同。若把该 API 当作物理成员序号，会丢失输入多重性与来源映射。

## 证据

锁定依赖为 zip =8.6.0，默认 features=false，仅启用 deflate-flate2-zlib-rs。上游源码 src/read/zip_archive.rs:35 保存 SharedBuilder.files: Vec；同文件49-52的 build 将每项 file_name_raw 作为 IndexMap key 插入；by_index 在530起读取的是该索引，折叠已经发生。

本项目 archive::tests::duplicate_names_and_contents_retain_distinct_occurrences 实际断言：直接 zip 读取 len=1，而 ArchiveInventory 物理 members=2、selected_dexes=2、两个内容 ID 不同。证据及命令在 artifacts/mdd-012/inventory-and-extraction.json，原始 stdout/stderr 同目录。

## 根因

库的遍历索引是名字索引内的序号，不能代表未经去重的中央目录记录序号。调用方式改成 by_index 并不能恢复先前已丢掉的同名记录。

## 最终方案

先在已捕获的自有不可变源字节上有界解析标准 ZIP 中央目录，逐项保留物理 ordinal、raw name、局部头和压缩数据范围。解压时给 zip 库提供单成员 Read+Seek 虚拟视图：原始数据前缀、该项原始中央头、只含该项的合成 EOCD。压缩 payload 没有复制或改写；解压结果使用有预算的自有字节，完整读到 EOF 触发库的 CRC 检查后才暴露。

成员身份绑定 source occurrence 和 central ordinal，物理 DEX 身份绑定内容与容器偏移，逻辑 DEX 候选另绑定 occurrence 与 header offset。资源只按成员身份从同一捕获代次读取，不把成员名当磁盘路径。目录与 selected DEX 字节完成、资源懒验证、DEX 事实资格分别记录。

## 失败方案

未采用直接遍历 ZipArchive 的方案：真实同名 fixture 已证明其名字索引丢项。没有通过改名、忽略重复成员或要求文件名唯一来改变输入定义，也没有另加解压依赖。最初已识别的直接库入口限制保留为针对回归，不包装成引擎功能通过。

## 验证范围

Windows x86_64/MSVC、Rust 1.99.0，8 个 archive 测试通过；与独立 Python fixture manifest 对照 8 个 ZIP 语料，其中 6 个成功 inventory、2 个坏 CRC/坏 magic 拒绝。还覆盖源同大小保留 mtime 改写/改名、同内容多输入、原始无效 UTF-8 文件名、0 预算、资源-only、数据描述符、声明长度不符与部分重叠物理范围。Clippy -D warnings 通过。

ZIP64、多卷、加密及其它 codec 未取得资格；资源字节在各自读取时校验，目录完成不代表所有未读资源已验证；标准 DEX 只生成 magic/字节范围候选，header、map、结构与代码事实资格由 MDD-013 及后续负责。没有 Linux 原生、HostLab 全量或性能结论。回滚时停用上层对新 archive 模块的显式调用，保留捕获快照及证据；不删除外部输入或重置其他工作树。
