#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成规则索引与 TCA 规则清单(betterleaks v1.9.0)。

仅在建机/维护时运行(需要 Python >= 3.11, 使用 tomllib)。
产出:
  1. config/rules_index.json —— 运行时使用的规则结构化索引(全部规则定义 + 组件依赖),
     运行时不再解析 TOML, 兼容 Python 3.7+ 节点。
  2. betterleaks_en.json    —— TCA 工具元数据 + checkrule_set 英文版(描述直接来自 TOML 源)。
  3. betterleaks.json       —— 中文版: 按规则名(real_name)对齐, 描述未变更时沿用已翻译的
     rule_title/description; TOML 描述变更 -> 译文过期提示重新翻译; 新增规则提示待翻译。
  4. stdout 打印与上一版 rules_index.json 的差异(新增/删除), 便于升级同步。

用法: python3 scripts/gen_rules.py
"""
import copy
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
BETTERLEAKS_JSON_EN = os.path.join(ROOT_DIR, "betterleaks_en.json")

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
        # TCA 规则包统一登记为内置规则, custom/labels 不随规则来源区分
        "custom": False,
        "languages": [],
        "solution": SOLUTION_TEXT,
        "owner": None,
        "labels": [],
        "description": meta.get("description") or rule_id,
        "disable": bool(meta.get("skipReport")),
    }


def _load_checkrules(path):
    """读取清单文件, 返回 ({real_name: rule}, {tool_name: tool_description})。"""
    rules, tool_desc = {}, {}
    if not os.path.exists(path):
        return rules, tool_desc
    with open(path, "r", encoding="utf-8") as fp:
        data = json.load(fp)
    for t in data:
        tool_desc[t.get("name")] = t.get("description")
        for r in t.get("checkrule_set") or []:
            rules[r["real_name"]] = r
    return rules, tool_desc


def apply_chinese_overlay(tool_meta, zh_path, en_prev_path):
    """按规则名(real_name)对齐, 把已翻译的中文 rule_title/description 叠加到新生成的清单上。

    翻译沿用条件(需同时满足):
      1. 上一版中文清单(betterleaks.json)中已有该规则的翻译;
      2. 上一版英文清单(betterleaks_en.json, 即上次生成时的 TOML 描述)与本次
         TOML 生成的描述一致 —— 描述未变更, 翻译仍然有效。
    否则:
      - 描述已变更 -> 译文过期, 沿用新描述并提示重新翻译(stale 列表);
      - 新增规则   -> 沿用 TOML 源描述(默认规则为英文), 提示待翻译(untranslated 列表);
      - 上一版英文清单不存在(首次运行) -> 无法比对, 仅按规则名对齐沿用翻译。
    已删除的规则不再出现在新清单中(以新生成的为准)。
    """
    prev_zh, zh_tool_desc = _load_checkrules(zh_path)
    prev_en, _ = _load_checkrules(en_prev_path)
    has_prev_en = bool(prev_en)

    stale, untranslated = [], []
    for t in tool_meta:
        new_set = []
        for r in t["checkrule_set"]:
            rid = r["real_name"]
            prev = prev_zh.get(rid)
            if prev and (not has_prev_en or prev_en[rid]["description"] == r["description"]):
                # 描述未变更: 沿用中文翻译
                r["rule_title"] = prev["rule_title"]
                r["description"] = prev["description"]
            elif prev:
                # 描述已变更: 译文过期, 沿用新描述
                stale.append(rid)
            else:
                # 新增规则
                untranslated.append(rid)
            new_set.append(r)
        t["checkrule_set"] = new_set
        if zh_tool_desc.get(t.get("name")):
            t["description"] = zh_tool_desc[t["name"]]
    return tool_meta, stale, untranslated


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

    # 中文版: 按规则名对齐叠加已有翻译。
    # 注意: 需在覆写英文清单之前执行, 才能拿到上一版英文描述做一致性比对;
    # 深拷贝避免原地修改污染英文清单。
    zh_meta, stale, untranslated = apply_chinese_overlay(
        copy.deepcopy(tool_meta), BETTERLEAKS_JSON, BETTERLEAKS_JSON_EN)

    with open(BETTERLEAKS_JSON_EN, "w", encoding="utf-8") as fp:
        json.dump(tool_meta, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    print(">> wrote %s (%d checkrules)" % (BETTERLEAKS_JSON_EN, len(checkrule_set)))

    with open(BETTERLEAKS_JSON, "w", encoding="utf-8") as fp:
        json.dump(zh_meta, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    print(">> wrote %s (%d checkrules)" % (BETTERLEAKS_JSON, len(checkrule_set)))
    if stale:
        print("!! 规则描述已变更, 中文翻译过期(已沿用新描述, 请更新翻译): %s" % ", ".join(stale))
    if untranslated:
        print(">> 新增规则待翻译(暂沿用 TOML 源描述): %s" % ", ".join(untranslated))


if __name__ == "__main__":
    main()
