# -*- coding: utf-8 -*-
"""按当前 OS/ARCH 选择 betterleaks 二进制, 并做完整性校验。"""
import hashlib
import os
import platform
import sys

from utils import ROOT_DIR

BIN_DIR = os.path.join(ROOT_DIR, "bin")

# (sys.platform, platform.machine 规范化) -> 二进制相对路径
PLATFORM_MAP = {
    ("linux", "amd64"): os.path.join("linux_amd64", "betterleaks"),
    ("linux", "x86_64"): os.path.join("linux_amd64", "betterleaks"),
    ("linux", "arm64"): os.path.join("linux_arm64", "betterleaks"),
    ("linux", "aarch64"): os.path.join("linux_arm64", "betterleaks"),
    ("darwin", "amd64"): os.path.join("mac_amd64", "betterleaks"),
    ("darwin", "x86_64"): os.path.join("mac_amd64", "betterleaks"),
    ("darwin", "arm64"): os.path.join("mac_arm64", "betterleaks"),
    ("win32", "amd64"): os.path.join("windows_amd64", "betterleaks.exe"),
    ("win32", "x86_64"): os.path.join("windows_amd64", "betterleaks.exe"),
    ("win32", "AMD64"): os.path.join("windows_amd64", "betterleaks.exe"),
}


def normalize_machine():
    machine = platform.machine() or ""
    return machine.lower()


def select_binary():
    """返回当前平台二进制绝对路径。

    支持环境变量 BETTERLEAKS_BIN 覆盖(需为存在的文件, 跳过 sha256 校验, 便于调试)。
    """
    override = os.environ.get("BETTERLEAKS_BIN", "").strip()
    if override:
        if not os.path.isfile(override):
            raise Exception("BETTERLEAKS_BIN points to a missing file: %s" % override)
        return override

    key = (sys.platform, normalize_machine())
    rel_path = PLATFORM_MAP.get(key)
    if not rel_path:
        raise Exception("unsupported platform: %s / %s" % (sys.platform, platform.machine()))
    bin_path = os.path.join(BIN_DIR, rel_path)
    if not os.path.isfile(bin_path):
        raise Exception("betterleaks binary not found: %s" % bin_path)

    # 打包后可能丢失可执行权限
    if os.name == "posix":
        try:
            mode = os.stat(bin_path).st_mode
            if not mode & 0o111:
                os.chmod(bin_path, 0o755)
        except OSError:
            pass

    verify_sha256(bin_path, rel_path.replace(os.sep, "/"))
    return bin_path


def verify_sha256(bin_path, rel_key):
    """校验落盘二进制 sha256 与 bin/VERSION 中记录是否一致(供应链完整性)。"""
    version_file = os.path.join(BIN_DIR, "VERSION")
    if not os.path.isfile(version_file):
        raise Exception("bin/VERSION not found, cannot verify binary")
    expected = None
    with open(version_file, "r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if line.startswith(rel_key + " "):
                expected = line.split("sha256=", 1)[1].strip()
                break
    if not expected:
        raise Exception("sha256 for %s not recorded in bin/VERSION" % rel_key)
    h = hashlib.sha256()
    with open(bin_path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected:
        raise Exception("sha256 mismatch for %s: expected %s, got %s" % (rel_key, expected, actual))
