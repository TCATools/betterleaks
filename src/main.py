# -*- coding: utf-8 -*-
"""betterleaks TCA 工具入口。

子命令:
  check —— 检查工具在当前环境是否可用(二进制可执行、配置合法、sha256 校验)
  scan   —— 扫描代码并输出 TCA result.json

环境变量(与 TCA 约定):
  SOURCE_DIR    待扫描代码目录
  TASK_REQUEST  任务请求文件路径
  RESULT_DIR    结果输出目录(默认 cwd)
  SCAN_FILES    待扫描文件列表(JSON, 已按过滤路径过滤)
  DIFF_FILES    增量 diff 文件列表(JSON, 仅增量扫描时存在)

安全约束:
  - 全程列表传参调用二进制, 不使用 shell;
  - 显式 -c 传入运行时配置, 不读取仓库内 .betterleaks.toml/.gitleaks.toml;
  - 不开启 --validation, 不与任何外部服务交互;
  - 报告与运行时配置中的敏感值由二进制 --redact 脱敏, 用后即删。
"""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config_builder
import platform_bin
import result_converter
from utils import (
    ROOT_DIR,
    detect_injection_symbols,
    get_int_env,
    get_path_filters,
    get_tool_env,
    load_task_params,
    run_cmd,
)

TCA_TOML = os.path.join(ROOT_DIR, "config", "tca.toml")

# 增量分批: 单批文件数与总路径长度上限(兼容 Windows 32K 命令行限制)
BATCH_MAX_FILES = 500
BATCH_MAX_BYTES = 16 * 1024
INCREMENTAL_FULLSCAN_THRESHOLD = 2000


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=2)


def read_file_list(env_key):
    path = os.environ.get(env_key)
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as rf:
            data = json.load(rf)
        if isinstance(data, list):
            return data
    return None


def check_usable():
    """检查二进制可执行 + 工具级配置合法。"""
    try:
        bin_path = platform_bin.select_binary()
    except Exception as err:
        print("[check] select binary failed: %s" % err)
        return False

    stdout, _, code = run_cmd([bin_path, "version"], timeout=60)
    if code != 0 or not stdout.strip():
        print("[check] binary version failed, exit=%s" % code)
        return False
    print("[check] betterleaks version: %s" % stdout.strip())

    stdout, stderr, code = run_cmd([bin_path, "config", "check", TCA_TOML], timeout=60)
    if code != 0:
        print("[check] tca.toml invalid: %s" % (stderr or stdout).strip()[:500])
        return False
    print("[check] config ok")
    return True


def build_scan_cmd(bin_path, runtime_toml, report_path, targets, tool_env):
    """构造扫描命令行(列表传参, 无 shell)。"""
    cmd = [
        bin_path, "dir",
        "-c", runtime_toml,
        "-r", report_path,
        "-f", "json",
        "--exit-code", "0",
        # 注意: --redact 设置了 NoOptDefVal=100, 必须用等号形式传值,
        # 否则会被当作无值开关(全遮蔽)且数值变成多余的位置参数
        "--redact=%d" % get_int_env(tool_env, "BETTERLEAKS_REDACT", 80, 0, 100),
        "--max-target-megabytes", str(get_int_env(tool_env, "BETTERLEAKS_MAX_TARGET_MB", 10, 0, 2048)),
        "--timeout", str(get_int_env(tool_env, "BETTERLEAKS_TIMEOUT", 3600, 60, 86400)),
        "--regex-engine", "re2",
        "--no-banner",
        "--no-color",
        "-l", "warn",
    ]
    for target in targets:
        detect_injection_symbols(target)
        cmd.append(target)

    min_confidence = (tool_env.get("BETTERLEAKS_MIN_CONFIDENCE") or "").strip().lower()
    if min_confidence:
        if min_confidence not in ("low", "medium", "high"):
            raise Exception("invalid BETTERLEAKS_MIN_CONFIDENCE: %s" % min_confidence)
        cmd += ["--confidence", min_confidence]
    return cmd, min_confidence


def batch_targets(file_list, source_dir):
    """把增量文件列表分批, 返回二维列表; 只保留存在的文件。"""
    existing = []
    for rel in file_list:
        if not isinstance(rel, str) or not rel:
            continue
        rel = rel.replace("\\", "/").lstrip("/")
        abs_path = rel if os.path.isabs(rel) else os.path.join(source_dir, rel)
        abs_path = os.path.normpath(abs_path)
        if os.path.isfile(abs_path):
            existing.append(abs_path)

    batches = []
    batch = []
    batch_bytes = 0
    for path in existing:
        size = len(path) + 1
        if batch and (len(batch) >= BATCH_MAX_FILES or batch_bytes + size > BATCH_MAX_BYTES):
            batches.append(batch)
            batch, batch_bytes = [], 0
        batch.append(path)
        batch_bytes += size
    if batch:
        batches.append(batch)
    return batches, existing


def run_scan():
    source_dir = os.environ.get("SOURCE_DIR")
    if not source_dir or not os.path.isdir(source_dir):
        raise Exception("SOURCE_DIR env not set or not a directory: %s" % source_dir)
    source_dir = os.path.abspath(source_dir)

    result_dir = os.environ.get("RESULT_DIR") or os.getcwd()
    os.makedirs(result_dir, exist_ok=True)
    result_path = os.path.join(result_dir, "result.json")

    task_params = load_task_params()
    tool_env = get_tool_env(task_params)
    bin_path = platform_bin.select_binary()
    index = config_builder.load_rules_index()

    re_inclusion, re_exclusion = get_path_filters(task_params)

    # 生成运行时配置并交由二进制校验
    runtime_toml = os.path.join(result_dir, "betterleaks_runtime.toml")
    enabled_rules, disabled_count = config_builder.build_runtime_config(
        index, task_params, TCA_TOML, runtime_toml)
    print("[scan] runtime config: %d rules enabled, %d disabled, %d custom/override"
          % (len(enabled_rules) or len(index["rules"]), disabled_count,
             len([e for e in task_params.get("rule_list") or []
                  if isinstance(e, dict) and (e.get("params") or e.get("rule_params"))])))

    _, stderr, code = run_cmd([bin_path, "config", "check", runtime_toml], timeout=60)
    if code != 0:
        raise Exception("runtime config invalid: %s" % (stderr or "").strip()[:500])

    # .betterleaksignore / .gitleaksignore: 仓库指纹忽略文件(存在时显式传入)
    ignore_targets = []
    for name in (".betterleaksignore", ".gitleaksignore"):
        if os.path.isfile(os.path.join(source_dir, name)):
            ignore_targets = ["-i", source_dir]
            break

    # 增量 or 全量
    diff_files = read_file_list("DIFF_FILES")
    if diff_files is not None and len(diff_files) == 0:
        # 增量扫描无变更文件: 无需扫描, 直接输出空结果
        print("[scan] incremental scan: no diff files, skip scan")
        write_json(result_path, [])
        print("[scan] result written: %s" % result_path)
        return 0

    def diff_rel_set(files):
        rels = set()
        for rel in files:
            rel = rel.replace("\\", "/").lstrip("/")
            if os.path.isabs(rel):
                rel = os.path.relpath(rel, source_dir).replace(os.sep, "/")
            rels.add(rel)
        return rels

    threshold = get_int_env(tool_env, "BETTERLEAKS_INCREMENTAL_THRESHOLD",
                            INCREMENTAL_FULLSCAN_THRESHOLD, 10, 100000)
    incremental = diff_files is not None and len(diff_files) <= threshold
    if incremental:
        batches, _ = batch_targets(diff_files, source_dir)
        print("[scan] incremental scan: %d files in %d batches" % (len(diff_files), len(batches)))
    else:
        if diff_files is not None:
            print("[scan] %d diff files exceed threshold %d, fallback to full scan + filter by diff list"
                  % (len(diff_files), threshold))
        batches = [[source_dir]]
        print("[scan] full scan: %s" % source_dir)

    # 只要存在 DIFF_FILES(增量), 无论分批扫描还是退化全量, 结果一律按 diff 集合过滤
    diff_set = diff_rel_set(diff_files) if diff_files is not None else None

    cmd_base, min_confidence = build_scan_cmd(
        bin_path, runtime_toml, os.path.join(result_dir, "betterleaks_report.json"),
        [], tool_env)

    timeout = get_int_env(tool_env, "BETTERLEAKS_TIMEOUT", 3600, 60, 86400) + 60
    report_paths = []
    try:
        for i, batch in enumerate(batches):
            report_path = os.path.join(result_dir, "betterleaks_report_%d.json" % i)
            cmd = list(cmd_base)
            # 替换 -r 参数为当前批次的报告路径
            cmd[cmd.index("-r") + 1] = report_path
            cmd += ignore_targets + batch
            print("[scan] run batch %d/%d ..." % (i + 1, len(batches)))
            stdout, stderr, code = run_cmd(cmd, timeout=timeout)
            if code != 0:
                raise Exception("betterleaks scan failed(exit=%d): %s"
                                % (code, (stderr or stdout).strip()[:500]))
            if os.path.exists(report_path):
                report_paths.append(report_path)

        # 合并转换
        result_lists = []
        for report_path in report_paths:
            result_lists.append(result_converter.convert_report(
                report_path, source_dir, enabled_rules, min_confidence,
                re_inclusion, re_exclusion, diff_set))
        results = result_converter.merge_results(result_lists)
        print("[scan] findings: %d (reports=%d)" % (len(results), len(report_paths)))
        write_json(result_path, results)
    finally:
        # 中间报告与运行时配置含(已脱敏的)敏感信息, 用后即删
        for report_path in glob.glob(os.path.join(result_dir, "betterleaks_report*.json")):
            try:
                os.remove(report_path)
            except OSError:
                pass
        try:
            os.remove(runtime_toml)
        except OSError:
            pass

    print("[scan] result written: %s" % result_path)
    return 0


def main():
    parser = argparse.ArgumentParser(description="betterleaks TCA tool")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check", help="check tool usable")
    sub.add_parser("scan", help="scan code")
    args = parser.parse_args()

    if args.command == "check":
        print(">> check tool usable ...")
        usable = check_usable()
        result_path = os.path.join(os.getcwd(), "check_result.json")
        if os.path.exists(result_path):
            os.remove(result_path)
        write_json(result_path, {"usable": usable})
        print(">> check result: %s" % usable)
        return 0 if usable else 1

    if args.command == "scan":
        print(">> start to scan code ...")
        return run_scan()

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
