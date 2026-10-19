#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合并 rules/custom/*.toml 生成工具级配置 config/tca.toml。

仅在建机/维护时运行(需要 Python >= 3.11, 使用 tomllib 解析 TOML)。
运行时不依赖本脚本, 运行时只读 config/rules_index.json。

用法: python3 scripts/merge_custom_rules.py
"""
import glob
import json
import os
import sys

try:
    import tomllib
except ImportError:
    print("need python >= 3.11 (tomllib)", file=sys.stderr)
    sys.exit(1)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CUSTOM_DIR = os.path.join(ROOT_DIR, "rules", "custom")
TCA_TOML = os.path.join(ROOT_DIR, "config", "tca.toml")
RULES_META = os.path.join(ROOT_DIR, "config", "rules_meta.json")

# 允许出现在自定义规则文件中的字段(与 betterleaks v1.9.0 config.rawRule 对齐,
# 出于安全考虑禁用 validate —— 工具不得与外部服务交互)
ALLOWED_RULE_FIELDS = (
    "id", "description", "regex", "path", "secretGroup", "entropy", "keywords",
    "tags", "specificity", "confidence", "components", "skipReport", "filter",
    "allowlist", "allowlists",
    # 集成层元字段: publish=false 表示仅用于测试, 不发布到 TCA 规则包(不出现在 tca.toml)
    "publish",
)
FORBIDDEN_RULE_FIELDS = ("validate", "analyze", "revoke")


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


def render_allowlist(allowlist, path):
    if not isinstance(allowlist, dict):
        raise ValueError("%s: allowlist 必须是表" % path)
    lines = ["allowlists = ["]
    lines.append("  {")
    first = True
    for key in ("description", "condition", "regexTarget"):
        value = allowlist.get(key)
        if isinstance(value, str) and value:
            if not first:
                lines[-1] += ","
            lines.append("    %s = %s" % (key, toml_escape(value)))
            first = False
    for key in ("paths", "regexes", "commits", "stopwords"):
        values = allowlist.get(key)
        if isinstance(values, list) and values:
            if not first:
                lines[-1] += ","
            lines.append("    %s = [%s]" % (key, ", ".join(toml_escape(str(v)) for v in values)))
            first = False
    lines.append("  },")
    lines.append("]")
    return lines


def render_rule(rule, seen_ids):
    if not isinstance(rule, dict):
        raise ValueError("rule 必须是 TOML 表")
    for key in FORBIDDEN_RULE_FIELDS:
        if rule.get(key):
            raise ValueError("自定义规则不允许使用 %s(禁止与外部服务交互): %s" % (key, rule.get("id")))
    rule_id = rule.get("id")
    if not rule_id or not isinstance(rule_id, str):
        raise ValueError("规则缺少 id: %r" % (rule,))
    if rule_id in seen_ids:
        raise ValueError("规则 ID 重复: %s" % rule_id)
    seen_ids.add(rule_id)
    if not rule.get("regex") and not rule.get("path"):
        raise ValueError("规则 %s 未定义 regex/path" % rule_id)
    # publish 是集成层元字段, 只写入 rules_meta.json, 不进入 tca.toml
    publish = rule.get("publish", True)
    if not isinstance(publish, bool):
        raise ValueError("规则 %s 的 publish 必须是布尔值" % rule_id)
    rule = {k: v for k, v in rule.items() if k != "publish"}

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
    allowlist = rule.get("allowlist")
    if isinstance(allowlist, dict) and allowlist:
        lines.extend(render_allowlist(allowlist, rule_id))
    components = rule.get("components")
    if isinstance(components, list) and components:
        for comp in components:
            lines.append("[[rules.components]]")
            lines.append("id = %s" % toml_escape(comp["id"]))
            if comp.get("optional"):
                lines.append("optional = true")
            if comp.get("within"):
                lines.append("within = %s" % toml_escape(comp["within"]))
    if rule.get("skipReport"):
        lines.append("skipReport = true")
    return "\n".join(lines), publish


def main():
    custom_files = sorted(glob.glob(os.path.join(CUSTOM_DIR, "*.toml")))
    seen_ids = set()
    rule_blocks = []
    global_filters = []
    rules_meta = {}

    for path in custom_files:
        with open(path, "rb") as fp:
            data = tomllib.load(fp)
        rules = data.get("rules")
        if rules and not isinstance(rules, list):
            raise ValueError("%s: [[rules]] 应为数组" % path)
        for rule in rules or []:
            block, publish = render_rule(rule, seen_ids)
            rule_blocks.append(block)
            rules_meta[rule["id"]] = {"publish": publish}
        for key in ("prefilter", "filter"):
            expr = data.get(key)
            if isinstance(expr, str) and expr.strip():
                global_filters.append((key, expr.strip(), path))

    content = [
        "# 由 scripts/merge_custom_rules.py 自动生成, 请勿手工编辑",
        "# 自定义规则源文件: rules/custom/*.toml",
        "",
        'title = "TCA betterleaks tool config"',
        "",
    ]

    if global_filters:
        for key, expr, path in global_filters:
            content.append("# 全局%s(来自 %s), 与默认配置的同名字段以 || 合并" % (key, os.path.basename(path)))
            content.append("%s = %s" % (key, toml_escape(expr)))
            content.append("")
    else:
        content.append("# 全局误报过滤示例(按需在 rules/custom/*.toml 顶层定义 prefilter/filter):")
        content.append('# prefilter = \'\'\'')
        content.append('# matchesAny(attributes["path"], [')
        content.append('#   `(^|/)testdata/`,')
        content.append('# ])')
        content.append("# '''")
        content.append("")

    content.append("[extend]")
    content.append("useDefault = true")
    content.append("")
    content.extend(rule_blocks)
    content.append("")

    with open(TCA_TOML, "w", encoding="utf-8") as fp:
        fp.write("\n".join(content))

    with open(RULES_META, "w", encoding="utf-8") as fp:
        json.dump({"rules": rules_meta}, fp, ensure_ascii=False, indent=1, sort_keys=True)

    unpublished = sorted(rid for rid, m in rules_meta.items() if m.get("publish") is False)
    print(">> wrote %s (%d custom rules, %d global filters)"
          % (TCA_TOML, len(rule_blocks), len(global_filters)))
    print(">> wrote %s (unpublished/test-only: %s)"
          % (RULES_META, ", ".join(unpublished) if unpublished else "none"))
    print(json.dumps({"rules": sorted(seen_ids)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
