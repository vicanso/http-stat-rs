#!/usr/bin/env sh

set -eu
printf '\n'

BOLD="$(tput bold 2>/dev/null || printf '')"
GREY="$(tput setaf 0 2>/dev/null || printf '')"
GREEN="$(tput setaf 2 2>/dev/null || printf '')"
YELLOW="$(tput setaf 3 2>/dev/null || printf '')"
BLUE="$(tput setaf 4 2>/dev/null || printf '')"
RED="$(tput setaf 1 2>/dev/null || printf '')"
NO_COLOR="$(tput sgr0 2>/dev/null || printf '')"

info() {
  printf '%s\n' "${BOLD}${GREY}>${NO_COLOR} $*"
}

warn() {
  printf '%s\n' "${YELLOW}! $*${NO_COLOR}"
}

error() {
  printf '%s\n' "${RED}x $*${NO_COLOR}" >&2
}

completed() {
  printf '%s\n' "${GREEN}✓${NO_COLOR} $*"
}

has() {
  command -v "$1" 1>/dev/null 2>&1
}

SUPPORTED_TARGETS="Linux_x86_64 Linux_arm64 Darwin_x86_64 Darwin_arm64 Windows_x86_64"

get_latest_release() {
  curl --silent "https://api.github.com/repos/vicanso/http-stat-rs/releases/latest" |
    grep '"tag_name":' |
    sed -E 's/.*"([^"]+)".*/\1/'
}

detect_platform() {
  platform="$(uname -s)"
  case "${platform}" in
    Linux*) platform="Linux" ;;
    Darwin*) platform="Darwin" ;;
    MINGW*|MSYS*|CYGWIN*) platform="Windows" ;;
    *)
      error "Unsupported platform: ${platform}"
      exit 1
      ;;
  esac
  printf '%s' "${platform}"
}

detect_arch() {
  arch="$(uname -m)"
  case "${arch}" in
    x86_64) arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      error "Unsupported architecture: ${arch}"
      exit 1
      ;;
  esac
  printf '%s' "${arch}"
}

download_and_install() {
  version="$1"
  platform="$2"
  arch="$3"

  case "${platform}" in
    Linux)
      if [ "${arch}" = "x86_64" ]; then
        filename="httpstat-linux-musl-x86_64.tar.gz"
      else
        filename="httpstat-linux-musl-aarch64.tar.gz"
      fi
      ;;
    Darwin)
      filename="httpstat-darwin-${arch}.tar.gz"
      ;;
    Windows)
      filename="httpstat-windows.exe.zip"
      ;;
  esac

  url="https://github.com/vicanso/http-stat-rs/releases/download/${version}/${filename}"

  info "Downloading http-stat-rs ${version}..."
  info "URL: ${url}"

  if has curl; then
    curl -sSL "${url}" -o "${filename}"
  elif has wget; then
    wget -q "${url}" -O "${filename}"
  else
    error "curl or wget not found."
    exit 1
  fi

  info "Extracting ${filename}..."
  extract_dir="httpstat_tmp"
  rm -rf "${extract_dir}"
  mkdir -p "${extract_dir}"

  if echo "${filename}" | grep -q ".zip$"; then
    if ! has unzip; then error "unzip not found"; exit 1; fi
    unzip -q "${filename}" -d "${extract_dir}"
  else
    tar -xzf "${filename}" -C "${extract_dir}"
  fi

  info "Installing..."
  
  # 兼容性改进：不再依赖 -executable 参数
  binary_name="httpstat"
  [ "${platform}" = "Windows" ] && binary_name="httpstat.exe"
  
  # 在解压目录中查找匹配的文件
  binary_path=$(find "${extract_dir}" -name "${binary_name}" -type f | head -n 1)

  # 如果按名字没找到，尝试找目录下唯一的普通文件（防止目录结构变化）
  if [ -z "${binary_path}" ]; then
    binary_path=$(find "${extract_dir}" -type f | head -n 1)
  fi

  if [ -z "${binary_path}" ]; then
    error "Binary not found in archive."
    ls -R "${extract_dir}"
    exit 1
  fi

  chmod +x "${binary_path}"
  
  target_bin="/usr/local/bin/httpstat"
  
  if [ "${platform}" = "Windows" ]; then
     info "Windows detected. Please manually move ${binary_path} to your PATH."
  else
    if has sudo; then
      sudo mv "${binary_path}" "${target_bin}"
    else
      mv "${binary_path}" "${target_bin}"
    fi
    completed "Installed to ${target_bin}"
  fi

  rm -rf "${filename}" "${extract_dir}"
}

main() {
  platform="$(detect_platform)"
  arch="$(detect_arch)"
  version="$(get_latest_release)"

  info "Detected: ${platform} (${arch})"
  
  target="${platform}_${arch}"
  if ! echo "${SUPPORTED_TARGETS}" | grep -q "${target}"; then
    error "Unsupported target: ${target}"
    exit 1
  fi

  download_and_install "${version}" "${platform}" "${arch}"
}

main