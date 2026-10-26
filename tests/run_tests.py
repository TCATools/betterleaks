#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端测试: 全量/增量/规则禁用/非法参数拒绝/组件 refs/路径过滤/脱敏。

用法: python3 tests/run_tests.py
"""
import json
import os
import subprocess
import tempfile

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT_DIR, "tests", "fixtures")

PASS, FAIL = 0, 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("[PASS] %s" % name)
    else:
        FAIL += 1
        print("[FAIL] %s %s" % (name, detail))


def run_scan(env_extra, result_dir, task_path=None):
    os.makedirs(result_dir, exist_ok=True)
    env = dict(os.environ)
    env["SOURCE_DIR"] = FIXTURES
    env["TASK_REQUEST"] = task_path or os.path.join(ROOT_DIR, "task_request.json")
    env["RESULT_DIR"] = result_dir
    env.update(env_extra)
    proc = subprocess.run(
        [os.environ.get("PYTHON", "python3"), os.path.join(ROOT_DIR, "src", "main.py"), "scan"],
        capture_output=True, text=True, env=env, cwd=ROOT_DIR)
    result_path = os.path.join(result_dir, "result.json")
    data = []
    if os.path.exists(result_path):
        with open(result_path, encoding="utf-8") as fp:
            data = json.load(fp)
    return proc.returncode, proc.stdout + proc.stderr, data


def write_task(td, mutate):
    task = json.load(open(os.path.join(ROOT_DIR, "task_request.json"), encoding="utf-8"))
    mutate(task)
    path = os.path.join(td, "task.json")
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(task, fp)
    return path


def rules_of(data):
    return {d["rule"] for d in data}


def main():
    # 1. 全量扫描: 五类规则全部检出
    with tempfile.TemporaryDirectory() as td:
        code, log, data = run_scan({}, os.path.join(td, "full"))
        rules = rules_of(data)
        expect = {"aws-access-token", "github-pat", "private-key", "tca-internal-token",
                  "my-project-token", "password-plaintext",
                  "tencent-secret-id", "tencent-secret-key"}
        check("full-scan", code == 0 and rules == expect, "rules=%s code=%s" % (rules, code))

        # 2. 脱敏: msg 不得包含明文假密钥
        text = json.dumps(data, ensure_ascii=False)
        leaks = [s for s in ("AKIAXQ7ZM4T2PYN5RW3E", "ghp_16C7uDS0TFakeTokenForTestingPurposes",
                            "TCA-INTERNAL-a1b2c3d4e5f6g7h8i9j0k1l2m3n4", "MYPROJECT-AbCdEf1234567890",
                            "Admin@123456", "AKIDFr9qlx382Gw8br6iS9gkhle565iszaGB",
                            "Gu5t9zXe8Km2Nq7Rw4Yp6Bv3Dc1Fh0Ja")
                 if s in text]
        check("redact", not leaks, "leaked=%s" % leaks)

        # 2a. password-plaintext 规则的 filter 生效: 误报样例不产出
        pw = [d for d in data if d["rule"] == "password-plaintext"]
        pw_text = json.dumps(pw, ensure_ascii=False)
        check("password-filter",
              len(pw) == 2 and "weak" not in pw_text and "please_change" not in pw_text,
              "findings=%d" % len(pw))

        # 2b. 结果格式: 无 extra_data, 有 end_line/end_column, msg 不带 confidence/描述
        bad_schema = [d for d in data if "extra_data" in d
                     or "end_line" not in d or "end_column" not in d
                     or not d["msg"].startswith("发现疑似敏感信息：")]
        check("result-schema", not bad_schema, str(bad_schema[:1]))

        # 3. 组件 refs
        aws = [d for d in data if d["rule"] == "aws-access-token"]
        check("component-refs", aws and bool(aws[0].get("refs")), str(aws[0].get("refs") if aws else None))

    # 4. 增量扫描: 只扫 diff 文件
    with tempfile.TemporaryDirectory() as td:
        diff = os.path.join(td, "diff.json")
        with open(diff, "w", encoding="utf-8") as fp:
            json.dump(["aws.py", "github.txt"], fp)
        code, log, data = run_scan({"DIFF_FILES": diff}, os.path.join(td, "incr"))
        check("incremental", code == 0 and rules_of(data) == {"aws-access-token", "github-pat"},
              "rules=%s" % rules_of(data))

    # 4b. 增量扫描但 diff 为空: 直接输出空结果, 不发起扫描
    with tempfile.TemporaryDirectory() as td:
        diff = os.path.join(td, "diff.json")
        with open(diff, "w", encoding="utf-8") as fp:
            json.dump([], fp)
        code, log, data = run_scan({"DIFF_FILES": diff}, os.path.join(td, "empty"))
        check("incremental-empty", code == 0 and data == [] and "skip scan" in log, "code=%s" % code)

    # 4c. diff 超过阈值退化为全量扫描: 结果仍按 diff 列表过滤
    with tempfile.TemporaryDirectory() as td:
        diff = os.path.join(td, "diff.json")
        # 14 个 diff 项(超过阈值 10), 其中只有 aws.py/github.txt 存在
        files = ["f%02d.py" % i for i in range(12)] + ["aws.py", "github.txt"]
        with open(diff, "w", encoding="utf-8") as fp:
            json.dump(files, fp)
        code, log, data = run_scan(
            {"DIFF_FILES": diff, "BETTERLEAKS_INCREMENTAL_THRESHOLD": "10"},
            os.path.join(td, "fallback"))
        check("incremental-fallback-filter",
              code == 0 and "fallback to full scan" in log
              and rules_of(data) == {"aws-access-token", "github-pat"},
              "rules=%s" % rules_of(data))

    # 5. 规则禁用: 只启用 private-key
    with tempfile.TemporaryDirectory() as td:
        task = write_task(td, lambda t: (t["task_params"].update(
            {"rules": ["private-key"], "rule_list": []})))
        code, log, data = run_scan({}, os.path.join(td, "onlypk"), task)
        check("disable-rules", code == 0 and rules_of(data) == {"private-key"},
              "rules=%s" % rules_of(data))

    # 6. 路径过滤: exclusion 过滤掉 aws.py
    with tempfile.TemporaryDirectory() as td:
        task = write_task(td, lambda t: t["task_params"].update(
            {"path_filters": {"inclusion": [], "exclusion": [], "re_inclusion": [],
                              "re_exclusion": ["^aws\\.py$"]}}))
        code, log, data = run_scan({}, os.path.join(td, "filter"), task)
        paths = {os.path.basename(d["path"]) for d in data}
        check("path-filter", code == 0 and "aws.py" not in paths, "paths=%s" % paths)

    # 7. 非法参数: 注入字符
    with tempfile.TemporaryDirectory() as td:
        task = write_task(td, lambda t: t["task_params"].update(
            {"rules": ["bad-rule"], "rule_list": [
                {"name": "bad-rule", "custom": True, "params": "regex=abc;rm -rf /"}]}))
        code, log, data = run_scan({}, os.path.join(td, "inj"), task)
        check("injection-reject", code != 0 and "Injection" in log, "code=%s" % code)

    # 8. 非法参数: 白名单外 key(validate 表达式)
    with tempfile.TemporaryDirectory() as td:
        task = write_task(td, lambda t: t["task_params"].update(
            {"rules": ["bad-rule"], "rule_list": [
                {"name": "bad-rule", "custom": True,
                 "params": "validate=1\nregex=abc[a-z]+"}]}))
        code, log, data = run_scan({}, os.path.join(td, "unknown"), task)
        check("unknown-param-reject", code != 0 and "不支持的规则参数" in log, "code=%s" % code)

    # 9. 未知规则名
    with tempfile.TemporaryDirectory() as td:
        task = write_task(td, lambda t: t["task_params"].update(
            {"rules": ["no-such-rule-xyz"], "rule_list": []}))
        code, log, data = run_scan({}, os.path.join(td, "unknownrule"), task)
        check("unknown-rule-reject", code != 0 and "未知规则" in log, "code=%s" % code)

    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
