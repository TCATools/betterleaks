# -*- coding: utf-8 -*-
"""运行时配置生成: 由 rules_index.json + task_params 生成 runtime.toml。

三层配置模型(利用 betterleaks [extend], 最大深度 2):
  runtime.toml(L3) --extend--> config/tca.toml(L2) --extend--> 内嵌默认规则(L1)

安全约束:
  - 用户只能提交白名单参数, 不允许直接传入 validate/filter 等表达式;
  - 覆盖默认规则时从索引取完整定义(索引已在构建期剥离 validate 表达式),
    禁止与外部服务交互;
  - 所有字符串经 TOML 转义写入, 生成后由二进制 `config check` 校验。
"""
import json
import os
import re

from utils import detect_injection_symbols

# 任务级规则参数白名单
RULE_PARAM_KEYS = ("regex", "keywords", "path", "secretGroup", "min_entropy", "confidence", "exclude_paths")
CONFIDENCE_VALUES = ("low", "medium", "high")
RULE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$")
MAX_REGEX_LEN = 1024
MAX_KEYWORDS = 20
MAX_EXCLUDE_PATHS = 50


def toml_escape(value):
    """输出 TOML 基本字符串(单行), 转义 \\ " 与控制字符。"""
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\u%04X" % ord(ch))
        else:
            out.append(ch)
    return '"%s"' % "".join(out)


def load_rules_index():
    index_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "config", "rules_index.json")
    with open(index_path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def parse_rule_params(raw_params):
    """解析 rule_params(多行 'k=v' 文本或 dict), 仅接受白名单 key。"""
    parsed = {}
    if isinstance(raw_params, dict):
        items = list(raw_params.items())
    elif isinstance(raw_params, str):
        items = []
        for line in raw_params.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            items.append((key.strip(), value.strip()))
    else:
        return parsed
    for key, value in items:
        if key not in RULE_PARAM_KEYS:
            raise Exception("不支持的规则参数: %s (允许: %s)" % (key, ", ".join(RULE_PARAM_KEYS)))
        detect_injection_symbols(value)
        parsed[key] = value
    return parsed


def _validate_regex(regex, what):
    if not regex:
        raise Exception("%s 缺少 regex 参数" % what)
    if len(regex) > MAX_REGEX_LEN:
        raise Exception("%s regex 超过长度上限 %d" % (what, MAX_REGEX_LEN))


def _split_list(value, max_count, what):
    values = [v.strip() for v in str(value).split(",") if v.strip()]
    if len(values) > max_count:
        raise Exception("%s 数量超过上限 %d" % (what, max_count))
    for v in values:
        detect_injection_symbols(v)
        if len(v) > 256:
            raise Exception("%s 单项超过 256 字符: %s..." % (what, v[:32]))
    return values


def apply_params(rule, params, rule_id):
    """把白名单参数合并进规则定义, 返回用于渲染的 dict。"""
    merged = dict(rule)
    merged.pop("custom", None)
    merged.pop("validate_stripped", None)

    if "regex" in params:
        _validate_regex(params["regex"], "规则 %s" % rule_id)
        merged["regex"] = params["regex"]
    if "keywords" in params:
        merged["keywords"] = _split_list(params["keywords"], MAX_KEYWORDS, "规则 %s keywords" % rule_id)
    if "path" in params:
        detect_injection_symbols(params["path"])
        merged["path"] = params["path"]
    if "secretGroup" in params:
        try:
            group = int(str(params["secretGroup"]).strip())
        except ValueError:
            raise Exception("规则 %s secretGroup 必须是整数" % rule_id)
        if group < 0 or group > 10:
            raise Exception("规则 %s secretGroup 超出范围 [0,10]" % rule_id)
        merged["secretGroup"] = group
    if "min_entropy" in params:
        try:
            entropy = float(str(params["min_entropy"]).strip())
        except ValueError:
            raise Exception("规则 %s min_entropy 必须是数字" % rule_id)
        if entropy < 0 or entropy > 8:
            raise Exception("规则 %s min_entropy 超出范围 [0,8]" % rule_id)
        merged["entropy"] = entropy
    if "confidence" in params:
        if params["confidence"] not in CONFIDENCE_VALUES:
            raise Exception("规则 %s confidence 非法: %s (允许: %s)"
                            % (rule_id, params["confidence"], "/".join(CONFIDENCE_VALUES)))
        merged["confidence"] = params["confidence"]
    if "exclude_paths" in params:
        patterns = _split_list(params["exclude_paths"], MAX_EXCLUDE_PATHS,
                               "规则 %s exclude_paths" % rule_id)
        allowlists = merged.get("allowlists") or []
        merged["allowlists"] = allowlists + [{"paths": patterns}]
    return merged


def render_rule(rule):
    lines = ["[[rules]]"]
    for key in ("id", "description", "regex", "path", "filter", "confidence"):
        value = rule.get(key)
        if isinstance(value, str) and value:
            lines.append("%s = %s" % (key, toml_escape(value)))
    for key in ("secretGroup", "specificity"):
        value = rule.get(key)
        if isinstance(value, int):
            lines.append("%s = %d" % (key, value))
    if isinstance(rule.get("entropy"), (int, float)):
        lines.append("entropy = %s" % repr(float(rule["entropy"])))
    for key in ("tags", "keywords"):
        values = rule.get(key)
        if isinstance(values, list) and values:
            lines.append("%s = [%s]" % (key, ", ".join(toml_escape(str(v)) for v in values)))
    for allowlist in rule.get("allowlists") or []:
        if not isinstance(allowlist, dict):
            continue
        lines.append("[[rules.allowlists]]")
        for key in ("description", "condition", "regexTarget"):
            value = allowlist.get(key)
            if isinstance(value, str) and value:
                lines.append("%s = %s" % (key, toml_escape(value)))
        for key in ("paths", "regexes", "commits", "stopwords"):
            values = allowlist.get(key)
            if isinstance(values, list) and values:
                lines.append("%s = [%s]" % (key, ", ".join(toml_escape(str(v)) for v in values)))
    for comp in rule.get("components") or []:
        if not isinstance(comp, dict):
            continue
        lines.append("[[rules.components]]")
        lines.append("id = %s" % toml_escape(comp.get("id", "")))
        if comp.get("optional"):
            lines.append("optional = true")
        if comp.get("within"):
            lines.append("within = %s" % toml_escape(comp["within"]))
    if rule.get("skipReport"):
        lines.append("skipReport = true")
    return "\n".join(lines)


def resolve_enabled(index, task_params):
    """计算 (启用规则集, 自定义/覆盖规则定义列表)。

    - task_params.rules 为空 → 启用全部规则;
    - 组件依赖闭包内的规则保持启用(组件规则通常 skipReport, 不产生对外结果);
    - rule_list 中带 params 的条目: id 在索引中 → 参数覆盖; 否则为项目自定义规则(必须提供 regex)。
    """
    all_rules = index["rules"]
    rule_deps = index.get("rule_deps") or {}
    rules_enabled = [str(r) for r in (task_params.get("rules") or []) if r]
    rule_list = task_params.get("rule_list") or []

    if rules_enabled:
        unknown = [r for r in rules_enabled if r not in all_rules and not _has_rule_def(rule_list, r)]
        if unknown:
            raise Exception("启用了未知规则(未在规则包/自定义规则中定义): %s" % ", ".join(unknown[:10]))

    # 组件依赖闭包
    enabled_set = set(rules_enabled)
    if enabled_set:
        queue = list(enabled_set)
        while queue:
            rid = queue.pop()
            for dep in rule_deps.get(rid) or []:
                if dep not in enabled_set:
                    enabled_set.add(dep)
                    queue.append(dep)

    custom_rules = []
    for entry in rule_list:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("real_name")
        if not name:
            continue
        name = str(name)
        if not RULE_NAME_RE.match(name):
            raise Exception("规则名非法: %s" % name)
        params = parse_rule_params(entry.get("params") or entry.get("rule_params"))
        if not params:
            continue
        if name in all_rules:
            # 已有规则的参数覆盖: 从索引取完整定义(已剥离 validate), 合并参数
            custom_rules.append(apply_params(all_rules[name], params, name))
        else:
            # 项目自定义规则: 必须提供 regex
            _validate_regex(params.get("regex", ""), "自定义规则 %s" % name)
            rule = {"id": name}
            custom_rules.append(apply_params(rule, params, name))

    return enabled_set, custom_rules


def _has_rule_def(rule_list, name):
    for entry in rule_list:
        if isinstance(entry, dict) and (entry.get("name") == name or entry.get("real_name") == name):
            return bool(entry.get("params") or entry.get("rule_params"))
    return False


def build_runtime_config(index, task_params, tca_toml_path, out_path):
    """生成 runtime.toml, 返回 (启用规则集, 禁用规则数)。"""
    enabled_set, custom_rules = resolve_enabled(index, task_params)

    all_ids = set(index["rules"].keys())
    disabled = sorted(all_ids - enabled_set) if enabled_set else []

    lines = [
        "# 由 TCA betterleaks 集成层自动生成, 请勿手工编辑",
        "",
        'title = "TCA runtime config"',
        "",
        "[extend]",
        "path = %s" % toml_escape(tca_toml_path),
    ]
    if disabled:
        lines.append("disabledRules = [%s]"
                     % ", ".join(toml_escape(rid) for rid in disabled))
    lines.append("")
    for rule in custom_rules:
        lines.append(render_rule(rule))
        lines.append("")

    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))

    return enabled_set, len(disabled)
