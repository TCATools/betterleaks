# Changelog

本文件记录 betterleaks TCA 集成工具的版本变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [1.0.0] - 2026-10-19

### Added

- 首个版本：集成 betterleaks v1.9.0 官方五端预编译二进制（linux/mac amd64+arm64、windows amd64）。
- TCA 入口 `check`/`scan`：平台二进制自动选择、sha256 供应链校验、全量/增量（分批 diff）扫描。
- 三层规则配置：内嵌默认（463 条）→ 工具级 `config/tca.toml`（内部规则示例 `tca-internal-token`）→ 任务级 runtime.toml（启用规则、参数覆盖、项目自定义规则）。
- 规则维护脚本：`fetch_bin.sh`（二进制下载校验）、`merge_custom_rules.py`、`gen_rules.py`（生成 `rules_index.json` 与 `betterleaks.json` 规则清单，含升级差异报告）；自定义规则支持 `publish = false` 元字段（仅测试用，不发布到规则包）；规则清单 `solution` 字段置空。
- 结果转换：脱敏、路径过滤、组件 refs（如 AWS Key ID + Secret 关联）、指纹去重。
- 端到端测试 9 项（`tests/run_tests.py`）与含假密钥样例仓库。
- 全量规则示例语料库 `tests/rule-examples/`（`gen_rule_examples.py`）：官方静态真阳性样例 + 规则正则反向采样（高熵不放回、组合规则组件拼接、path 规则文件名生成），经二进制验证闭环保留可命中样例，覆盖 436/465 条规则并输出 `COVERAGE.md` 覆盖率报告。
- 安全设计：无 shell 列表传参、显式 `-c` 防仓库配置绕过、参数白名单拒绝表达式注入、剥离 `validate` 表达式、默认不外联、RE2 正则防 ReDoS。
