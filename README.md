# betterleaks TCA 集成工具

基于 [betterleaks](https://github.com/betterleaks/betterleaks) v1.9.0 的敏感信息扫描工具，通过官方预编译二进制调用，支持 linux/mac(amd64+arm64)/windows(amd64) 五端，支持 TCA 规则包开关、规则参数调整与项目自定义规则。

## 目录说明

| 路径 | 说明 |
|---|---|
| `tool.json` | TCA 入口声明（`check_cmd` / `run_cmd`） |
| `betterleaks.json` | TCA 工具元数据 + 规则清单（`checkrule_set`，脚本生成） |
| `bin/<平台>/` | 官方五端二进制，`bin/VERSION` 记录版本与 sha256 |
| `config/betterleaks-default.toml` | 默认规则快照（463 条，仅维护用） |
| `config/tca.toml` | 工具级配置：内部规则 + `[extend] useDefault` |
| `config/rules_meta.json` | 自定义规则元信息（`publish=false` 的规则仅测试用，不发布到规则包） |
| `config/rules_index.json` | 运行时规则索引（结构化定义 + 组件依赖） |
| `rules/custom/*.toml` | 内部自定义规则源文件 |
| `src/` | 运行时代码（仅标准库，Python 3.7+） |
| `scripts/` | 维护脚本：二进制下载 / 规则合并 / 规则清单生成 |
| `tests/` | 含假密钥样例与端到端测试 |
| `tests/rule-examples/` | 全量规则示例语料库（每条示例注释规则名，`COVERAGE.md` 为覆盖率报告） |

## 本地调试

```bash
bash test.sh                  # 用 tests/fixtures 作为扫描目标跑 check + scan
python3 tests/run_tests.py    # 9 项端到端测试
```

环境变量与 TCA 约定：`SOURCE_DIR`、`TASK_REQUEST`、`RESULT_DIR`、`SCAN_FILES`、`DIFF_FILES`。任务 `envs` 可调扫描行为：`BETTERLEAKS_REDACT`（脱敏比例，默认 80）、`BETTERLEAKS_MAX_TARGET_MB`（默认 10）、`BETTERLEAKS_TIMEOUT`（默认 3600s）、`BETTERLEAKS_MIN_CONFIDENCE`、`BETTERLEAKS_INCREMENTAL_THRESHOLD`（增量退化阈值，默认 2000）、`BETTERLEAKS_BIN`（调试用二进制覆盖）。

## 结果格式（result.json）

```json
[{
  "path": "/abs/path/file.py",     // 绝对路径
  "line": 3, "column": 19,
  "end_line": 3, "end_column": 61,  // 匹配结束位置
  "msg": "发现疑似敏感信息：REDACTED",   // 密钥已脱敏, 不带规则描述/置信度(规则信息在规则包中维护)
  "rule": "aws-access-token",
  "refs": [{"line": 2, "msg": "关联组件 ...", "tag": "aws-secret-access-key", "path": "..."}]
}]
```

## 规则调整

| 场景 | 操作 |
|---|---|
| 启用/禁用规则 | TCA 规则包勾选（`task_params.rules`） |
| 新增内部规则 | 在 `rules/custom/*.toml` 增加 `[[rules]]`（禁止 `validate` 字段；`publish = false` 表示仅测试用、不发布到规则包），执行下方维护命令并同步规则包 |
| 覆盖默认规则 | `rules/custom/*.toml` 写同 ID 规则整条覆盖 |
| 项目自定义规则 | TCA 自定义规则 `params`，如 `regex=XXX-[A-Za-z0-9]{16,}\nkeywords=XXX\nconfidence=high` |
| 调整已有规则 | `params` 支持 `regex/keywords/path/secretGroup/min_entropy/confidence/exclude_paths`（白名单，拒绝任何表达式） |
| 单个误报 | 代码行加 `betterleaks:allow`，或仓库根 `.betterleaksignore` 登记指纹 |

维护命令（需 Python ≥3.11）：

```bash
python3 scripts/merge_custom_rules.py   # rules/custom/*.toml → config/tca.toml
python3 scripts/gen_rules.py            # 刷新 rules_index.json + betterleaks.json（打印规则差异）
python3 scripts/gen_rule_examples.py    # 重新生成 tests/rule-examples/ 规则示例语料库
python3 tests/run_tests.py              # 回归
```

## 升级流程

```bash
scripts/fetch_bin.sh <tag> <release下载根地址>   # 下载五端二进制并校验 checksums
# 用新版本默认配置覆盖 config/betterleaks-default.toml
# 更新 scripts/gen_rules.py 中 BETTERLEAKS_VERSION，执行维护命令与回归
```

## 安全设计

- 列表传参调用二进制，不使用 shell；外部输入经注入符号检查。
- 始终显式 `-c` 传入运行时配置，不读取仓库内 `.betterleaks.toml`/`.gitleaks.toml`（防仓库配置绕过检测）。
- 不开启 `--validation`，规则索引构建期剥离 `validate` 表达式，自定义规则参数走白名单：**全程不与外部服务交互**。
- 报告密钥由二进制 `--redact=80` 脱敏，中间文件用后即删；正则使用默认 RE2 引擎（线性匹配）。
- 二进制下载校验官方 `checksums.txt`，运行前校验落盘 sha256。
