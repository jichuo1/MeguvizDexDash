# MDD-025 Manifest 实现记录

## 现象

资源字符串池和 DEX 字符串规则不能通用。AXML 属性同时携带可缺省 rawValue 和编译后的 Res_value；原值为空、原值不存在、TYPE_NULL undefined、TYPE_NULL empty、空文本及尚未解析的资源 ID 都是不同事实。多个 namespace 前缀可以指向同一 URI，而编译节点只记录 URI 和 local name，无法证明原始 QName 使用了哪个前缀。

## 证据

`tests/fixtures/manifest/manifest.json` 固定 76 个向量，其中 14 正例、62 负例；独立 encoder、Python ElementTree、固定 SDK37 AAPT2 与原始 AOSP ResourceTypes/XmlDom 源码共同提供预期。`small-aapt-summary.json` 的九个小 AXML 正例均完整比较 11 节点、23 属性。公开 NewPipe 同 SHA 的完整树为 305 节点、411 属性；`public-full-tree-comparison.json` 记录全部 namespace/name/parent/resource ID/raw/typed-display 相同。固定 A0 `get_manifest` 真实请求完整消费 6 个权限页、12 行，字段对照见 `a0-summary-comparison.json`，关闭响应也已保存。

## 根因

AXML 的 source offset、pool index、typed rawbits 和展示文本处于不同表示层。AAPT2 对 rawValue 为空的属性省略 `(Raw: "")` 展示，不能据此把空原值改成 NULL；本次公开语料正好有一个 `taskAffinity` 属性触发该区别。quick-xml 切片 reader 的 BOM 位置计数也不能直接当成原成员绝对位置；初轮真实测试在 BOM 正例失败，明确暴露了 3 字节偏差。将新 API 记忆成旧版 BytesDecl.attributes() 同样造成真实编译失败，已根据本机 0.42.0 源码改用公开 Attributes 构造函数。

## 最终方案

文档持有调用者的同一个不可变 Arc，不重开文件。所有范围都以原成员字节计量，start-node 范围明确仅覆盖起始 tag/chunk。AXML 独立校验 chunk/字符串池/style/resource-map/namespace/tree/attrs；文本 XML 使用已批准 quick-xml 0.42.0 词法与规范化接口，并额外验证 XML 名称、字符、根、命名空间、DTD/实体禁用及声明顺序。资源 UTF-16 保留孤立代理 code units，结构名称要求有效标量，UTF-8 严格拒绝坏编码。预算在解码/克隆/分配前检查，还为 namespace 扫描设置 work 限额。前缀来源标明 source QName、唯一 binding 或歧义；多 uses-sdk 保留所有节点并明确 convenience projection 歧义。资源引用均未解析，不推 ARSC/overlay/exported 默认。调用示例由 ResourceByteEvidence 绑定 snapshot/member/content 身份，再以其同 Arc 构建文档。

## 失败方案

未保留“零测试”为通过：首次模块未 export 的 cargo test 实际运行 0 个 Manifest 测试，只用于揭示接入缺失，随后主代理添加 export 后才执行真实测试。没有把编译报错或 BOM 范围错误标为 unsupported。没有为了让 AAPT2 展示差分相等而清除 native 空 rawValue；独立读取原始 AXML rawValue index 验证了它确实存在。没有把多个前缀选最后一个的展示选择宣称为原始事实，也没有把多 SDK 声明静默覆盖成单值。

## 验证范围

Windows x86_64 Rust stable 1.99.0 的全 mdd-input 16 个单元测试、0 个忽略、Clippy -D warnings 和绑定示例构建均成功，命令/终态/完整输出保存 `final/`。独立 Python 检查使用 -O 仍有效，不依赖会消失的 assert。固定 A0 仅作为请求/字段对照，不生成新引擎结果；两个 framework enum 的字符串展示转换仅在证据适配器中出现。没有运行私有大 APK，没有发布或默认切换，没有性能资格；Linux 原生执行待主代理 CI。MDD-042 仍负责 MCP/展示 XML/分页，MDD-072 仍负责完整 ARSC/config/overlay/资源工具。回滚时按明确文件清单撤回本次 manifest 模块/例子/fixtures，并由主代理撤回 export；保留原始 evidence，不覆盖 archive/snapshot 或其他事实层。
