#!/usr/bin/env bash
# osmedic 一键部署：在全新 openEuler 24.03 上装齐依赖并编译
# 评分对应：工程质量-复现脚本项（评委在干净环境复核的入口）
set -euo pipefail
cd "$(dirname "$0")"

echo "[1/3] 安装依赖…"
# 部分 VM 只配置 Everything，stress-ng 位于 EPOL。仓库只对本次安装有效，
# 不改 /etc/yum.repos.d，不关闭 RPM 签名校验。
source /etc/os-release
repo_options=()
if [[ "$ID" == "openEuler" && "$VERSION_ID" == "24.03" ]]; then
    base="https://mirrors.huaweicloud.com/openeuler/openEuler-24.03-LTS"
    arch=$(uname -m)
    for entry in "osmedic-everything,$base/everything/$arch/" "osmedic-epol,$base/EPOL/main/$arch/"; do
        name=${entry%%,*}
        repo_options+=("--repofrompath=$entry" "--setopt=$name.gpgcheck=1"
                       "--setopt=$name.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-openEuler")
    done
fi
sudo dnf "${repo_options[@]}" install -y gcc clang llvm make bpftool libbpf-devel \
                    elfutils-libelf-devel pkgconf python3 stress-ng fio sysstat git

echo "[2/3] 编译全部探针与注入工具…"
make

echo "[3/3] 完成。快速自检：sudo ./build/execsnoop（另开终端敲 ls，应有事件输出）"
