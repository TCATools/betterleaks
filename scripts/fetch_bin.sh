#!/usr/bin/env bash
# 下载 betterleaks 官方 release 预编译二进制并校验入库
# 用法: ./scripts/fetch_bin.sh <version> <download_base_url>
#   version          release tag, 如 v2.0.0-rc.2
#   download_base_url  release 下载根地址, 如 https://github.com/betterleaks/betterleaks/releases/download
set -euo pipefail

VERSION="${1:-v1.9.0}"
BASE_URL="${2:-https://github.com/betterleaks/betterleaks/releases/download}"
STRIP_VERSION="${VERSION#v}"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# 目标目录 -> 官方资产平台后缀
declare -A TARGETS=(
  [linux_amd64]="linux_x64"
  [linux_arm64]="linux_arm64"
  [mac_amd64]="darwin_x64"
  [mac_arm64]="darwin_arm64"
  [windows_amd64]="windows_x64"
)

RELEASE_URL="${BASE_URL}/${VERSION}"
echo ">> download checksums.txt"
curl -sSL --retry 3 -o "${TMP_DIR}/checksums.txt" "${RELEASE_URL}/checksums.txt"

mkdir -p "${BIN_DIR}"

VERSION_FILE="${BIN_DIR}/VERSION"
{
  echo "version=${VERSION}"
  echo "source=${RELEASE_URL}"
} > "${VERSION_FILE}"

for target_dir in "${!TARGETS[@]}"; do
  platform="${TARGETS[${target_dir}]}"
  asset="betterleaks_${STRIP_VERSION}_${platform}.tar.gz"
  if [[ "${platform}" == windows_* ]]; then
    asset="betterleaks_${STRIP_VERSION}_${platform}.zip"
  fi

  echo ">> download ${asset}"
  curl -sSL --retry 3 -o "${TMP_DIR}/${asset}" "${RELEASE_URL}/${asset}"

  echo ">> verify sha256 of ${asset}"
  # checksums.txt 中记录的是压缩包的哈希, 在解包前校验
  expected="$(grep " ${asset}\$" "${TMP_DIR}/checksums.txt" | awk '{print $1}')"
  if [[ -z "${expected}" ]]; then
    echo "checksum not found for ${asset}" >&2
    exit 1
  fi
  actual="$(sha256sum "${TMP_DIR}/${asset}" | awk '{print $1}')"
  if [[ "${expected}" != "${actual}" ]]; then
    echo "sha256 mismatch for ${asset}: expected ${expected}, got ${actual}" >&2
    exit 1
  fi

  out_dir="${BIN_DIR}/${target_dir}"
  rm -rf "${out_dir}"
  mkdir -p "${out_dir}"
  if [[ "${asset}" == *.zip ]]; then
    unzip -oq "${TMP_DIR}/${asset}" -d "${out_dir}"
    mv "${out_dir}/betterleaks.exe" "${out_dir}/betterleaks.exe.tmp" 2>/dev/null || true
    find "${out_dir}" -type f ! -name 'betterleaks.exe.tmp' -delete
    mv "${out_dir}/betterleaks.exe.tmp" "${out_dir}/betterleaks.exe"
  else
    tar -xzf "${TMP_DIR}/${asset}" -C "${out_dir}"
    find "${out_dir}" -type f ! -name 'betterleaks' -delete
  fi
  bin_name="betterleaks"
  [[ "${asset}" == *.zip ]] && bin_name="betterleaks.exe"
  chmod +x "${out_dir}/${bin_name}" 2>/dev/null || true

  bin_sha="$(sha256sum "${out_dir}/${bin_name}" | awk '{print $1}')"
  echo "${target_dir}/${bin_name} sha256=${bin_sha}" | tee -a "${VERSION_FILE}"
done

echo ">> done. binaries in ${BIN_DIR}"
