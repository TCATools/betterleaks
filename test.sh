#!/usr/bin/env bash
# 本地调试脚本: 用 tests/fixtures 作为扫描目标跑一次 check + scan
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
export SOURCE_DIR="${SOURCE_DIR:-${ROOT_DIR}/tests/fixtures}"
export RESULT_DIR="${RESULT_DIR:-${ROOT_DIR}/tests/output}"
export TASK_REQUEST="${TASK_REQUEST:-${ROOT_DIR}/task_request.json}"

mkdir -p "${RESULT_DIR}"

echo ">> check"
python3 src/main.py check

echo ">> scan"
python3 src/main.py scan

echo ">> result:"
cat "${RESULT_DIR}/result.json"
