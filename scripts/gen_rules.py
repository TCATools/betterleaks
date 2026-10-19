#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成规则索引与 TCA 规则清单(betterleaks v1.9.0)。

仅在建机/维护时运行(需要 Python >= 3.11, 使用 tomllib)。
产出:
  1. config/rules_index.json —— 运行时使用的规则结构化索引(全部规则定义 + 组件依赖),
     运行时不再解析 TOML, 兼容 Python 3.7+ 节点。
  2. betterleaks.json        —— TCA 工具元数据 + checkrule_set, 用于平台登记规则包。
  3. stdout 打印与上一版 rules_index.json 的差异(新增/删除), 便于升级同步。

用法: python3 scripts/gen_rules.py
"""
import json
import os
import sys

try:
    import tomllib
except ImportError:
    print("need python >= 3.11 (tomllib)", file=sys.stderr)
    sys.exit(1)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TOML = os.path.join(ROOT_DIR, "config", "betterleaks-default.toml")
TCA_TOML = os.path.join(ROOT_DIR, "config", "tca.toml")
RULES_META = os.path.join(ROOT_DIR, "config", "rules_meta.json")
RULES_INDEX = os.path.join(ROOT_DIR, "config", "rules_index.json")
BETTERLEAKS_JSON = os.path.join(ROOT_DIR, "betterleaks.json")

BETTERLEAKS_VERSION = "1.9.0"

# 运行时允许写入覆盖规则的字段; validate 一律剥离(禁止外部交互)
RULE_FIELDS = (
    "id", "description", "regex", "path", "secretGroup", "entropy", "keywords",
    "tags", "specificity", "confidence", "components", "skipReport", "filter",
    "allowlists",
)

SEVERITY_MAP = {"high": "error", "medium": "warning"}

# 修复建议由 TCA 平台规则包统一维护, 规则 JSON 中置空
SOLUTION_TEXT = ""


def load_rules(path):
    with open(path, "rb") as fp:
        data = tomllib.load(fp)
    return data.get("rules") or []


def strip_rule(rule, custom):
    out = {"custom": bool(custom)}
    for field in RULE_FIELDS:
        value = rule.get(field)
        if value in (None, "", [], 0, False):
            continue
        out[field] = value
    if rule.get("validate"):
        # 默认规则中带 validate 表达式的规则: 保留规则本身但剥离表达式。
        # 注意: v1.9.0 中 validate 表达式可能请求外部服务, 运行时由集成层统一剥离,
        # 单独运行 betterleaks 时(不带 --validate)默认不会发起外联。
        out["validate_stripped"] = True
    return out


def to_camel(rule_id):
    parts = rule_id.replace("_", "-").split("-")
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def build_checkrule(rule_id, meta):
    confidence = (meta.get("confidence") or "low").lower()
    return {
        "real_name": rule_id,
        "display_name": to_camel(rule_id),
        "severity": SEVERITY_MAP.get(confidence, "info"),
        "category": "security",
        "rule_title": (meta.get("description") or rule_id)[:200],
        "rule_params": None,
        "custom": bool(meta.get("custom")),
        "languages": [],
        "solution": SOLUTION_TEXT,
        "owner": None,
        "labels": meta.get("tags") or [],
        "description": meta.get("description") or rule_id,
        "disable": bool(meta.get("skipReport")),
    }


def main():
    default_rules = load_rules(DEFAULT_TOML)
    tca_rules = load_rules(TCA_TOML)

    index_rules = {}
    overridden = set()
    for rule in default_rules:
        rule_id = rule["id"]
        if rule_id in index_rules:
            raise SystemExit("默认规则 ID 重复: %s" % rule_id)
        index_rules[rule_id] = strip_rule(rule, custom=False)

    for rule in tca_rules:
        rule_id = rule["id"]
        if rule_id in index_rules:
            overridden.add(rule_id)
        index_rules[rule_id] = strip_rule(rule, custom=True)

    # 组件依赖闭包: rule -> 依赖的组件规则 id
    rule_deps = {}
    for rule_id, meta in index_rules.items():
        deps = []
        for comp in meta.get("components") or []:
            if isinstance(comp, dict) and comp.get("id"):
                deps.append(comp["id"])
        if deps:
            rule_deps[rule_id] = deps

    index = {
        "betterleaks_version": BETTERLEAKS_VERSION,
        "rules": index_rules,
        "rule_deps": rule_deps,
    }

    # 与上一版差异
    if os.path.exists(RULES_INDEX):
        with open(RULES_INDEX, "r", encoding="utf-8") as fp:
            old = json.load(fp)
        old_ids = set(old.get("rules") or {})
        new_ids = set(index_rules)
        added = sorted(new_ids - old_ids)
        removed = sorted(old_ids - new_ids)
        if added or removed or overridden:
            print(">> 规则差异: 新增 %d, 删除 %d, 覆盖 %d" % (len(added), len(removed), len(overridden)))
            for rid in added:
                print("  + %s" % rid)
            for rid in removed:
                print("  - %s" % rid)
            for rid in sorted(overridden):
                print("  ~ %s" % rid)

    with open(RULES_INDEX, "w", encoding="utf-8") as fp:
        json.dump(index, fp, ensure_ascii=False, indent=1, sort_keys=True)
    print(">> wrote %s (%d rules)" % (RULES_INDEX, len(index_rules)))

    # TCA 规则清单
    # rules_meta.json 中 publish=false 的自定义规则仅保留在索引/tca.toml 中用于测试,
    # 不发布到 TCA 规则包
    unpublished = set()
    if os.path.exists(RULES_META):
        with open(RULES_META, "r", encoding="utf-8") as fp:
            meta_data = json.load(fp)
        for rid, m in (meta_data.get("rules") or {}).items():
            if m.get("publish") is False:
                unpublished.add(rid)

    checkrule_set = []
    for rule_id in sorted(index_rules):
        meta = index_rules[rule_id]
        if meta.get("skipReport"):
            continue  # 组件规则等不对外展示
        if rule_id in unpublished:
            continue  # 测试专用规则, 不发布
        checkrule_set.append(build_checkrule(rule_id, meta))
    if unpublished:
        print(">> unpublished rules (test only): %s" % ", ".join(sorted(unpublished)))

    tool_meta = [{
        "name": "betterleaks",
        "display_name": "Betterleaks",
        "description": "基于 betterleaks 的敏感信息检测工具, 支持 460+ 内置规则与自定义规则",
        "license": "MIT License",
        "libscheme_set": [],
        "image_url": "",
        "task_processes": ["analyze", "datahandle"],
        "scan_app": "codelint",
        "scm_url": "https://github.com/betterleaks/betterleaks",
        "run_cmd": "python3 src/main.py",
        "check_cmd": "python3 src/main.py check",
        "envs": " \npython_version=3",
        "build_flag": False,
        "checkrule_set": checkrule_set,
        "open_user": True,
        "open_saas": False,
        "show_display_name": True,
        "rule_name_control": None,
        "remote_work_enabled": None,
    }]

    with open(BETTERLEAKS_JSON, "w", encoding="utf-8") as fp:
        json.dump(tool_meta, fp, ensure_ascii=False, indent=2)
    print(">> wrote %s (%d checkrules)" % (BETTERLEAKS_JSON, len(checkrule_set)))


if __name__ == "__main__":
    main()
