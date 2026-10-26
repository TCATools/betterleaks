# betterleaks 工具集成方案与计划

> 参考模板：`/data/tools/demo-tool`（入口与协议），`/data/tools/trivy`（多平台二进制布局），`/data/tools/semgrep`（规则元数据 `checkrule_set` 与规则生成脚本）
> 工具源码：`/data/install/betterleaks`（Go，**v1.9.0** 稳定版，仅用于查阅能力/规则格式）
> 二进制：betterleaks 官方 release 预编译二进制（v1.9.0，五端）
> 集成目录：`/data/tools/betterleaks`
> 文档日期：2026-10-19（v2 已实现，本文档与实现同步）

---

## 1. 需求

| # | 需求 | 落地要点 |
|---|------|----------|
| R1 | 通过**二进制**调用，支持**多端** | 官方预编译 linux/mac(amd64+arm64)/windows(amd64) 静态二进制，`main.py` 按 OS/Arch 自动选择 |
| R2 | 支持**新增规则 / 调整规则** | 三层 TOML 配置（内置默认 → 工具级自定义 → 任务级运行时生成），配合 TCA 规则包开关、规则参数、自定义规则 |

---

## 2. betterleaks v1.9.0 关键能力调研结论

| 项 | 结论 | 依据 |
|----|------|------|
| 语言/构建 | Go 1.25，官方以 goreleaser 发布各平台预编译二进制（`CGO_ENABLED=0` 纯静态），本集成直接取用 | `go.mod`、`.goreleaser.yml` |
| 官方资产命名 | `betterleaks_1.9.0_<GOOS>_<GOARCH>.tar.gz|.zip`（amd64 平台后缀为 `x64`），附 `checksums.txt` | release 页面 |
| 本地扫描命令 | `betterleaks dir [path...]`（别名 `file`/`directory`），支持多路径；`detect` 为 git 仓库扫描 | `cmd/directory.go` |
| 输出 | `-r/--report-path xxx -f/--report-format json`，**JSON 为 Finding 数组**（Go 字段名）；另支持 csv/junit/sarif/template | `report/json.go` |
| Finding 字段 | `RuleID/Description/StartLine/EndLine/StartColumn/EndColumn/Match/Secret/File/Fingerprint/Tags/ComponentSets/Attributes`；置信度在 `Attributes["confidence"]`，路径在 `File`（由 `Attributes["path"]` 同步） | `report/finding.go` |
| 组合规则 | `ComponentSets[].components[]`（注意小写 tag）给出组件匹配位置，如 AWS Key ID + Secret | `report/finding.go:119-150` |
| 脱敏 | `--redact[=PERCENT]`（uint，缺省 100），**JSON 报告同样生效** | `cmd/root.go:94-95` |
| 退出码 | 无泄漏 0；有泄漏 = `--exit-code`（默认 1）；错误 1 | `cmd/root.go` |
| 配置发现顺序 | `--config` > `BETTERLEAKS_CONFIG`/`GITLEAKS_CONFIG` > `BETTERLEAKS_CONFIG_TOML` > **(扫描目标)/.betterleaks.toml|.gitleaks.toml** > 内嵌默认 | `cmd/root.go:41-43,202-232` |
| 默认规则 | 内嵌 `config/betterleaks.toml`，**463** 条规则（gitleaks 风格字段） | 源码 config/ |
| 规则字段 | `id/description/regex/path/secretGroup/entropy/keywords/tags/specificity/confidence/allowlist(s)/components/skipReport/filter/validate` | `config/config.go:52-82` |
| 全局字段 | `title/extend/rules/allowlist(s)/minVersion/prefilter/filter` | `config/config.go:30-46` |
| 配置继承 | `[extend] path/url/useDefault + disabledRules`；同 ID 整条覆盖；**最大继承深度 2**（`runtime → tca → default` 三层可用）；v1 额外支持 `extend.url`（本集成禁用） | `config/config.go:152-157,347` |
| 在线校验 | `--validation` 默认 **false**（"enable validation of findings against live APIs"），不开启则不外联 | `cmd/root.go:104` |
| 规则校验 | `betterleaks config check <toml>`、`config show`、`config path`、`version` | `cmd/config.go`、`cmd/version.go` |
| 忽略机制 | `.betterleaksignore`/`.gitleaksignore`（`-i` 指定，默认 `.`）、行内 `betterleaks:allow` / `gitleaks:allow` | `cmd/root.go:98` |
| 其他有用参数 | `--max-target-megabytes`、`--timeout`、`--confidence`、`--enable-rule/--disable-rule/--isolate-rule`、`--regex-engine re2`（默认，线性匹配防 ReDoS）、`--max-decode-depth`、`--max-archive-depth` | `cmd/root.go:78-113` |

### 安全要点（v1 特有）

1. **配置绕过风险**：v1 会自动读取**扫描目标目录**下的 `.betterleaks.toml`/`.gitleaks.toml`（当未显式传 `--config` 时）。仓库可借此关闭检测规则。**集成层必须始终显式 `-c` 传运行时配置**。
2. **外联风险**：部分默认规则带 `validate` 表达式（如 AWS、GitHub 在线验证）。`--validation` 默认关闭，且命令行完全由集成层构造、不透传该参数；运行时覆盖规则时也从不生成 `validate` 字段（索引构建期已剥离）。
3. `extend.url` 会让配置从远程拉取，集成层生成的 TOML 永远只用 `extend.path`/`useDefault`。

---

## 3. 总体架构

```
TCA 任务 ──► tool.json(check_cmd / run_cmd)
              │
              ▼
         src/main.py  ──① 读 SOURCE_DIR / TASK_REQUEST / SCAN_FILES / DIFF_FILES / RESULT_DIR
              │       ──② 平台选择 bin/<os>_<arch>/betterleaks[.exe] + sha256 校验
              │       ──③ 生成 runtime.toml（启用规则 + 任务级自定义规则 + 参数, extend config/tca.toml）
              │       ──④ betterleaks config check 校验 runtime.toml
              │       ──⑤ subprocess 列表传参调用二进制(无 shell, 显式 -c, 不开 --validation)
              │       ──⑥ 解析 JSON 报告 → 过滤 → 转换 TCA result.json
              │       ──⑦ 清理中间报告与 runtime.toml(含脱敏后的敏感值)
              ▼
     ${RESULT_DIR}/result.json
```

### 3.1 目录结构（`/data/tools/betterleaks`，已实现）

```
betterleaks/
├── tool.json                     # check_cmd / run_cmd
├── betterleaks.json              # TCA 工具元数据 + checkrule_set（421 条，脚本生成）
├── bin/
│   ├── linux_amd64/betterleaks
│   ├── linux_arm64/betterleaks
│   ├── mac_amd64/betterleaks
│   ├── mac_arm64/betterleaks
│   ├── windows_amd64/betterleaks.exe
│   └── VERSION                   # release tag + 各二进制 sha256
├── config/
│   ├── betterleaks-default.toml  # 默认规则快照（463 条，仅用于生成索引/比对，运行时用内嵌默认）
│   ├── tca.toml                  # 工具级配置：[extend] useDefault=true + 内部规则
│   ├── rules_meta.json           # 自定义规则元信息（publish=false 表示仅测试用、不发布到规则包）
│   └── rules_index.json          # 运行时规则索引（结构化定义 + 组件依赖闭包，免 TOML 解析）
├── rules/custom/*.toml           # 自定义规则源文件（按业务分文件维护）
├── src/
│   ├── main.py                  # check / scan 入口
│   ├── platform_bin.py           # 平台识别、二进制定位、sha256 校验
│   ├── config_builder.py         # runtime.toml 生成（参数白名单校验）
│   ├── result_converter.py       # 报告转换（脱敏、过滤、去重、组件 refs）
│   └── utils.py                  # 命令执行、注入检查、路径过滤、环境解析
├── scripts/
│   ├── fetch_bin.sh              # 下载官方五端二进制并校验 checksums.txt
│   ├── merge_custom_rules.py      # rules/custom/*.toml → config/tca.toml
│   ├── gen_rules.py               # 默认+自定义规则 → rules_index.json + betterleaks.json（含差异报告）
│   └── gen_rule_examples.py       # 生成全量规则示例语料库 tests/rule-examples/（静态样例+正则反向采样+验证闭环）
├── tests/
│   ├── fixtures/                  # 含假密钥的样例（AWS/GitHub/私钥/内部令牌/项目令牌）
│   ├── rule-examples/              # 全量规则示例语料库（官方静态样例 + 正则反向采样，COVERAGE.md 覆盖率报告）
│   ├── run_tests.py               # 13 项端到端测试
│   └── output/                    # 本地调试输出（gitignore）
├── task_request.json / test.sh    # 本地调试
├── README.md / CHANGELOG.md
└── docs/PLAN.md                   # 本文档
```

---

## 4. 方案一：二进制调用与多端支持（R1）【已实现】

### 4.1 平台映射（`src/platform_bin.py`）

| `sys.platform` | `platform.machine()` | 二进制 |
|---|---|---|
| `linux` | `x86_64` / `amd64` | `bin/linux_amd64/betterleaks` |
| `linux` | `aarch64` / `arm64` | `bin/linux_arm64/betterleaks` |
| `darwin` | `x86_64` | `bin/mac_amd64/betterleaks` |
| `darwin` | `arm64` | `bin/mac_arm64/betterleaks` |
| `win32` | `AMD64` / `x86_64` | `bin/windows_amd64/betterleaks.exe` |
| 其他 | - | `check` 返回 `usable=false`，`scan` 报错退出 |

- 路径基于脚本目录拼接，不依赖 cwd；posix 下自动补 `+x`。
- `BETTERLEAKS_BIN` 环境变量可覆盖二进制路径（调试用，需为存在的文件）。
- 每次调用前校验落盘二进制 sha256 与 `bin/VERSION` 记录一致（供应链完整性）。

### 4.2 调用方式

`check`：
```
<bin> version                    # 退出码 0 且有版本输出
<bin> config check config/tca.toml   # 工具级配置合法
```
写 `check_result.json`：`{"usable": true/false}`。

`scan`（全量，v1.9.0）：
```
<bin> dir <SOURCE_DIR>
      -c <RESULT_DIR>/betterleaks_runtime.toml      # 显式配置, 防止读取仓库内 .betterleaks.toml
      -r <RESULT_DIR>/betterleaks_report_N.json
      -f json
      --exit-code 0                # 有发现也返回 0, 非 0 一律视为执行失败
      --redact=<N>                 # 默认 80, 报告中密钥部分遮蔽
      --max-target-megabytes <M>   # 默认 10, 可由任务环境变量调整
      --timeout <S>                # 二进制自身超时, 默认 3600
      --regex-engine re2           # 线性正则, 防 ReDoS
      --no-banner --no-color -l warn
      [-i <SOURCE_DIR>]            # 存在 .betterleaksignore/.gitleaksignore 时传入
      [--confidence low|medium|high]  # BETTERLEAKS_MIN_CONFIDENCE 设置时
```
- **不开启 `--validation`**，不使用 `detect`/`git`/`protect`/`validate` 等命令，全程不与外部服务交互。
- `subprocess.Popen(list)` 列表传参，禁用 shell；目标路径经注入符号检查。
- Python 侧另有超时保护（二进制超时 + 60s），超时 kill 进程并报错。
- 增量扫描：`DIFF_FILES` 存在且非空、数量 ≤ 阈值（默认 2000，`BETTERLEAKS_INCREMENTAL_THRESHOLD` 可调）时，diff 文件按 ≤500 个/批、单批命令行 ≤16KB 分批传给 `dir`，合并多份报告；`DIFF_FILES` 为空列表时直接输出空结果不扫描；超过阈值退化为全量扫描，**结果仍按 diff 列表过滤**；已删除文件跳过。

### 4.3 二进制获取（`scripts/fetch_bin.sh`）

直接使用官方 release 预编译二进制，**不自行编译**。
- 五端：`linux_x64`/`linux_arm64`/`darwin_x64`/`darwin_arm64`/`windows_x64`（不含 windows_arm64）。
- 下载后按官方 `checksums.txt` 校验压缩包哈希，解包入库，`bin/VERSION` 记录 release tag 与各二进制 sha256。
- URL 作为脚本参数传入，不写死；`check` 阶段还会校验落盘 sha256。
- 大体积二进制建议 git-lfs 管理。

---

## 5. 方案二：规则配置与调整（R2）【已实现】

### 5.1 三层配置模型

利用 betterleaks `[extend]`（最大深度 2，恰好容纳三层）：

```
Layer 3  <RESULT_DIR>/betterleaks_runtime.toml   (任务级, main.py 每次扫描生成, 用后即删)
   │  [extend] path = config/tca.toml
   │           disabledRules = [未启用的规则]
   │  [[rules]] TCA 平台自定义规则 / 带参数调整后的规则(索引取完整定义, 已剥离 validate)
   ▼
Layer 2  config/tca.toml   (工具级, 随工具版本发布, 由 rules/custom/*.toml 合并生成)
   │  [extend] useDefault = true
   │  [[rules]] 公司内部新增规则 / 同 ID 覆盖默认规则
   │  prefilter / filter 全局误报过滤(可选)
   ▼
Layer 1  内嵌默认配置 (463 条, 随官方二进制)
```

### 5.2 规则元数据与 TCA 规则包

`scripts/gen_rules.py`（构建机 Python ≥3.11，用 `tomllib`）生成：

- `config/rules_index.json` —— 全部规则的结构化定义（**构建期剥离 `validate` 表达式**）+ 组件依赖闭包。运行时只读 JSON，节点 Python 3.7+ 即可。
- `betterleaks.json` —— TCA `checkrule_set`（421 条，`skipReport` 组件规则不外显）：

| TCA 字段 | 来源 |
|---|---|
| `real_name` | 规则 `id`（与 result.json 的 `rule` 一致） |
| `display_name` | `id` 转驼峰 |
| `severity` | `confidence` 映射：high→`error`，medium→`warning`，low/空→`info` |
| `category` | `security` |
| `rule_title` / `description` | 规则 `description` |
| `labels` | `tags` |
| `custom` | 工具级自定义规则为 `true` |
| `solution` | 置空（修复建议由 TCA 平台规则包统一维护） |
| `disable` | `skipReport` 规则为 `true` |

- `publish = false` 的自定义规则（如测试用的 `tca-internal-token`）保留在 `tca.toml`/规则索引中用于测试，但**不发布**到 `betterleaks.json` 规则包（元信息经 `merge_custom_rules.py` 写入 `config/rules_meta.json`）。

- 升级时输出规则**差异报告**（新增/删除/覆盖），便于同步 TCA 规则包。

### 5.3 支持的规则调整方式

| 场景 | 方式 | 生效层级 | 维护方 |
|---|---|---|---|
| 启用/禁用规则 | TCA 规则包勾选 → `task_params.rules` → runtime.toml `disabledRules`（组件依赖闭包内的规则自动保留） | L3 | 项目用户 |
| 新增内部规则 | `rules/custom/<biz>.toml` 新增 `[[rules]]` → `merge_custom_rules.py` → `gen_rules.py` → 同步规则包 | L2 | 工具管理员 |
| 修改默认规则 | `rules/custom/override.toml` 同 ID 整条覆盖（gitleaks 字段：`regex/secretGroup/entropy/keywords/allowlist...`） | L2 | 工具管理员 |
| 全局误报过滤 | custom toml 顶层 `prefilter`/`filter`（与默认配置 `||` 合并） | L2 | 工具管理员 |
| 规则级参数调整 | TCA 规则 `params`（白名单 key，见 5.4）→ runtime.toml 同 ID 覆盖 | L3 | 项目用户 |
| 项目自定义规则 | TCA 自定义规则 `params` 提供 `regex` 等 → runtime.toml 新增 `[[rules]]` | L3 | 项目用户 |
| 单个误报忽略 | 代码中 `betterleaks:allow` 注释，或仓库根 `.betterleaksignore` 指纹 | 源码 | 项目用户 |
| 扫描参数 | 任务 `envs`：`BETTERLEAKS_REDACT`(0-100,默认80)、`BETTERLEAKS_MAX_TARGET_MB`(默认10)、`BETTERLEAKS_TIMEOUT`(默认3600)、`BETTERLEAKS_MIN_CONFIDENCE`、`BETTERLEAKS_INCREMENTAL_THRESHOLD`(默认2000,超过退化为全量扫描+按 diff 过滤)、`BETTERLEAKS_BIN`(调试) | L3 | 项目用户 |

### 5.4 任务级 `params` 约定

`params` 为多行 `key=value` 文本，**只接受白名单 key**：

| key | 适用 | 说明 |
|---|---|---|
| `regex` | 自定义规则（必填） | RE2 语法（默认引擎，线性匹配防 ReDoS），长度 ≤1024 |
| `keywords` | 自定义/已有规则 | 逗号分隔，≤20 项，用于预过滤提速 |
| `path` | 自定义规则 | 文件路径正则，≤256 字符 |
| `secretGroup` | 自定义/已有规则 | 捕获组序号 0-10（整数） |
| `min_entropy` | 自定义/已有规则 | 浮点 0-8，写入规则 `entropy` 字段（gitleaks 语义：低于阈值丢弃） |
| `confidence` | 自定义规则 | `low/medium/high` 枚举 |
| `exclude_paths` | 已有规则 | 逗号分隔路径正则，≤50 项，生成规则级 `allowlists.paths` |

安全约束（`src/config_builder.py`）：
- **不允许**传入 `validate`/`filter`/`prefilter` 等原始表达式（防止表达式注入与外联请求），未知 key 直接报错。
- 规则名校验 `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`；覆盖规则从索引取完整定义（**已剥离 validate**）再合并参数；自定义规则名不得与已有规则冲突。
- 所有字符串 TOML 转义写入；生成后 `betterleaks config check` 校验，失败报错退出。

### 5.5 启用规则与组件依赖

- 依赖闭包由 `gen_rules.py` 预生成到 `rules_index.json.rule_deps`；启用某组合规则（如 `aws-access-token`）时其组件（`aws-secret-access-key`）保持启用，否则组合规则失效。
- 结果转换按 `task_params.rules` 二次过滤（兜底）；`rules` 为空视为启用全部。

---

## 6. 结果转换（`src/result_converter.py`）

betterleaks v1.9.0 JSON Finding → TCA `result.json`：

| TCA 字段 | 映射 |
|---|---|
| `path` | `File`（相对则拼 `SOURCE_DIR`），规范化为绝对路径 |
| `line` / `end_line` | `StartLine` / `EndLine` |
| `column` / `end_column` | `StartColumn` / `EndColumn`（无则取起始值） |
| `rule` | `RuleID` |
| `msg` | `"发现疑似敏感信息：{Secret(已脱敏)}"`。不带 confidence 与规则描述——规则标题/描述/severity 已在 TCA 规则包（`betterleaks.json` 的 `rule_title/description/severity`）中维护，结果里重复展示没有信息量 |
| `refs` | `ComponentSets[].components[]` 中其他组件位置（如 AWS Key ID ↔ Secret），`tag` 为组件规则 ID |

过滤链：规则启用过滤 → 路径过滤（`path_filters.re_exclusion/re_inclusion`，exclude 优先）→ 增量 diff 过滤 → 最小置信度过滤 → 按 `(path, line, rule, fingerprint)` 去重 → 排序输出。

---

## 7. 安全设计

| 风险 | 措施 |
|---|---|
| 命令注入 | 列表传参，禁用 shell；所有外部值（目标路径、参数值）先做注入符号检查 + 类型/枚举校验 |
| 密钥二次泄露 | 默认 `--redact=80`；`msg` 只含脱敏值；中间报告与 runtime.toml 用后即删；日志不打印匹配值 |
| 仓库配置绕过检测 | **始终显式 `-c`**，不读取仓库内 `.betterleaks.toml`/`.gitleaks.toml`；仅 `.betterleaksignore` 指纹和行内 `betterleaks:allow` 生效 |
| 外部服务交互 / SSRF | **不传 `--validation`**（默认 false），禁用 `validate/detect git/protect` 等命令；索引构建期剥离 `validate` 表达式；自定义规则参数白名单拒绝任何表达式；运行时生成的 TOML 永远不用 `extend.url` |
| 表达式注入 / ReDoS | 用户侧只能提交白名单参数；正则走默认 RE2 引擎（线性匹配）并限制长度；生成后 `config check` 校验 |
| 二进制供应链 | 官方 release 二进制，下载时校验 `checksums.txt`，`bin/VERSION` 记录 sha256，每次调用前再校验落盘 sha256 |
| HMAC 密钥 | 不使用指纹 HMAC 功能；如未来启用，密钥仅从环境变量读取，不落盘 |

---

## 8. 实施与验收【已完成】

### 8.1 验收结果（tests/run_tests.py，9/9 通过）

1. ✅ 全量扫描：AWS 组合规则、GitHub PAT、私钥、内部令牌（工具级自定义）、项目令牌（任务级自定义）5 类全部检出，行号/列号正确。
2. ✅ 脱敏：result.json 中不含任何明文假密钥（`--redact` 生效）。
3. ✅ 组合规则 `refs`：aws-access-token 结果携带 aws-secret-access-key 组件位置。
4. ✅ 增量扫描：`DIFF_FILES` 只报 diff 文件问题。
5. ✅ 规则禁用：规则包只勾选 `private-key` 时仅产出该规则问题（459 条正确禁用）。
6. ✅ 路径过滤：`re_exclusion` 命中文件被过滤。
7. ✅ 注入拒绝：`regex=abc;rm -rf /` 被注入检查拒绝。
8. ✅ 参数白名单：`validate=...` 等白名单外 key 被拒绝。
9. ✅ 未知规则名被拒绝。
10. ⏳ 五端冒烟：linux_amd64 已验证；linux_arm64/mac/windows 需对应节点执行 `bash test.sh`（`check` 含 sha256 校验与 `config check`）。

### 8.2 工具升级流程

1. `scripts/fetch_bin.sh <new-tag> <base-url>` 下载新版本五端二进制（校验 checksums 入库）；
2. 更新 `config/betterleaks-default.toml` 为新版本默认规则快照，`scripts/gen_rules.py` 的 `BETTERLEAKS_VERSION`；
3. 执行 `gen_rules.py`：刷新 `rules_index.json` + `betterleaks.json`，检查差异报告与 L2 覆盖规则冲突；
4. `python3 tests/run_tests.py` 回归；更新 CHANGELOG，同步 TCA 规则包。

---

## 9. 遗留事项

| # | 事项 | 说明 |
|---|---|---|
| 1 | mac/linux_arm64/windows 实机冒烟 | 在对应节点跑 `bash test.sh` 即可（check 含 sha256 校验） |
| 2 | severity 映射口径 | 当前按 confidence（high→error/medium→warning/low→info），如平台侧有安全等级规范可再调整 |
| 3 | git 历史扫描 | v1 支持 `detect`（git log 全历史），一期仅 `dir` 工作区扫描；历史扫描可作为二期开关 |
| 4 | 大仓库性能 | `dir` 全量扫描性能未在大仓库上压测；可按需调 `BETTERLEAKS_MAX_TARGET_MB` 与增量阈值 |
| 5 | `dir` 输出 `File` 为绝对路径 | 已实测确认（传入绝对路径时）；转换层仍保留相对路径兜底 |
