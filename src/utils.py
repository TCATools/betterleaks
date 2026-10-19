# -*- coding: utf-8 -*-
"""通用工具: 命令执行(列表传参/无 shell)、注入检查、任务参数与环境解析。"""
import json
import os
import re
import subprocess

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 扫描行为相关的环境变量白名单(来源: 进程环境 + task_params.envs)
ENV_KEYS = (
    "BETTERLEAKS_BIN",
    "BETTERLEAKS_REDACT",
    "BETTERLEAKS_MAX_TARGET_MB",
    "BETTERLEAKS_TIMEOUT",
    "BETTERLEAKS_MIN_CONFIDENCE",
    "BETTERLEAKS_INCREMENTAL_THRESHOLD",
)


def detect_injection_symbols(cmd_str):
    """检查字符串中是否存在命令注入符号, 存在则抛异常。"""
    if not cmd_str:
        return
    symbols = "|".join(["\\n", ";", "&+", "\\|+", "`", "\\$\\("])
    match_chars = re.findall(symbols, cmd_str)
    if match_chars:
        raise Exception("Find Injection Symbols(%s) in command: %s" % (match_chars, cmd_str))


def run_cmd(cmd_args, timeout=None, cwd=None):
    """执行外部命令, 列表传参且不使用 shell, 防止命令注入。"""
    if not isinstance(cmd_args, (list, tuple)):
        raise Exception("cmd_args must be a list")
    p = subprocess.Popen(
        list(cmd_args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        stdout, stderr = p.communicate()
        raise Exception("command timeout after %ss: %s" % (timeout, cmd_args[0]))
    return stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace"), p.returncode


def load_task_params():
    """读取 TASK_REQUEST 环境变量指向的任务请求文件, 返回 task_params。"""
    task_request_file = os.environ.get("TASK_REQUEST")
    if not task_request_file or not os.path.exists(task_request_file):
        raise Exception("TASK_REQUEST env not set or file not found: %s" % task_request_file)
    with open(task_request_file, "r", encoding="utf-8") as rf:
        task_request = json.load(rf)
    return task_request.get("task_params") or {}


def parse_envs(envs):
    """解析 task_params.envs, 兼容多行字符串('k=v' 每行一条)与 dict 两种形态。"""
    parsed = {}
    if isinstance(envs, dict):
        for key, value in envs.items():
            parsed[str(key).strip()] = str(value).strip()
    elif isinstance(envs, str):
        for line in envs.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            parsed[key.strip()] = value.strip()
    return parsed


def get_tool_env(task_params):
    """合并 进程环境 与 task envs 中白名单内的 BETTERLEAKS_* 配置(任务侧优先)。"""
    merged = {}
    for key in ENV_KEYS:
        if key in os.environ:
            merged[key] = os.environ[key]
    for key, value in parse_envs(task_params.get("envs")).items():
        if key in ENV_KEYS:
            merged[key] = value
    return merged


def get_int_env(envs, key, default, min_value, max_value):
    value = envs.get(key)
    if value in (None, ""):
        return default
    try:
        ivalue = int(str(value).strip())
    except ValueError:
        raise Exception("invalid %s value: %r (expect int)" % (key, value))
    if ivalue < min_value or ivalue > max_value:
        raise Exception("%s out of range [%d, %d]: %d" % (key, min_value, max_value, ivalue))
    return ivalue


def get_path_filters(task_params):
    """把 task_params.path_filters 编译为 (re_inclusion, re_exclusion) 正则列表, exclude 优先。"""
    filters = task_params.get("path_filters") or {}

    def compile_list(patterns):
        compiled = []
        for pattern in patterns or []:
            if not pattern:
                continue
            detect_injection_symbols(pattern)
            compiled.append(re.compile(pattern))
        return compiled

    return compile_list(filters.get("re_inclusion")), compile_list(filters.get("re_exclusion"))


def path_filtered(rel_path, re_inclusion, re_exclusion):
    """判断相对路径是否被过滤: exclusion 优先级高于 inclusion。"""
    rel_path = rel_path.replace(os.sep, "/")
    for pattern in re_exclusion:
        if pattern.search(rel_path):
            return True
    if re_inclusion:
        for pattern in re_inclusion:
            if pattern.search(rel_path):
                return False
        return True
    return False
