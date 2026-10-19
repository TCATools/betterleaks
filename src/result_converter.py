# -*- coding: utf-8 -*-
"""报告转换: betterleaks JSON 报告(v1.9.0, Finding 数组) -> TCA result.json。

报告中的 Secret/Match 已由二进制 --redact 脱敏, 转换层不再输出明文。
"""
import json
import os

from utils import path_filtered

CONF_ORDER = {"": 1, "low": 1, "medium": 2, "high": 3}


def _normalize_path(file_path, source_dir):
    if not file_path:
        return ""
    file_path = file_path.replace("\\", "/")
    if not os.path.isabs(file_path):
        file_path = os.path.join(source_dir, file_path)
    return os.path.normpath(file_path)


def _rel_path(file_path, source_dir):
    rel = os.path.relpath(file_path, source_dir)
    return rel.replace(os.sep, "/")


def convert_report(report_path, source_dir, enabled_rules, min_confidence,
                   re_inclusion, re_exclusion, diff_files=None):
    """读取单份报告并转换为 TCA 结果列表(未写盘)。"""
    with open(report_path, "r", encoding="utf-8") as fp:
        findings = json.load(fp)
    if not isinstance(findings, list):
        raise Exception("unexpected report format in %s: expect JSON array" % report_path)

    results = []
    seen = set()
    diff_set = set(diff_files) if diff_files else None

    for f in findings:
        rule_id = f.get("RuleID") or ""
        if enabled_rules and rule_id not in enabled_rules:
            continue

        attributes = f.get("Attributes") or {}
        confidence = (f.get("Confidence") or attributes.get("confidence") or "").lower()
        if min_confidence and CONF_ORDER.get(confidence, 1) < CONF_ORDER.get(min_confidence, 1):
            continue

        file_path = _normalize_path(f.get("File") or attributes.get("path") or "", source_dir)
        if not file_path or not os.path.exists(file_path):
            continue
        rel = _rel_path(file_path, source_dir)
        if path_filtered(rel, re_inclusion, re_exclusion):
            continue
        if diff_set is not None and rel not in diff_set:
            continue

        line = int(f.get("StartLine") or 0)
        column = int(f.get("StartColumn") or 0)
        end_line = int(f.get("EndLine") or line)
        end_column = int(f.get("EndColumn") or column)
        fingerprint = f.get("Fingerprint") or ""
        key = (file_path, line, rule_id, fingerprint)
        if key in seen:
            continue
        seen.add(key)

        secret = f.get("Secret") or f.get("Match") or ""
        # msg 不带 confidence 与规则描述: 规则标题/描述已在 TCA 规则包(betterleaks.json)中维护,
        # 结果里重复展示没有信息量, 只保留脱敏后的命中内容
        msg = "发现疑似敏感信息：%s" % secret

        refs = []
        for cset in f.get("ComponentSets") or []:
            for comp in cset.get("Components") or cset.get("components") or []:
                comp_rule = comp.get("RuleID") or ""
                if comp_rule == rule_id:
                    continue
                refs.append({
                    "line": int(comp.get("StartLine") or 0),
                    "msg": "关联组件 %s: %s" % (comp_rule, comp.get("Secret") or comp.get("Match") or ""),
                    "tag": comp_rule,
                    "path": file_path,
                })

        results.append({
            "path": file_path,
            "line": line,
            "column": column,
            "end_line": end_line,
            "end_column": end_column,
            "msg": msg,
            "rule": rule_id,
            "refs": refs,
        })
    return results


def merge_results(result_lists):
    """合并多批扫描结果并按 (path, line, rule) 去重。"""
    merged = []
    seen = set()
    for results in result_lists:
        for item in results:
            key = (item["path"], item["line"], item["rule"])
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
    merged.sort(key=lambda x: (x["path"], x["line"], x["rule"]))
    return merged
