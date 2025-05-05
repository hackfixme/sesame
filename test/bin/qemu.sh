#!/usr/bin/env bash
# External dependencies:
# - https://www.qemu.org/
set -eEuo pipefail
[ "${DEBUG:-0}" -eq 1 ] && set -x

_currdir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
source "${_currdir}/utils.sh"

# All arguments with their default values.
disk_file=""
disk_size=""
backing_file=""
iso_file=""
daemonize=0


_qemu="qemu-system-x86_64"
_qemu_img="qemu-img"
_opts=(
  -cpu host -smp 4 -m 4G -enable-kvm -M q35
  -drive "if=pflash,format=raw,readonly=on,file=${_currdir}/ovmf/code.fd"
  -drive "if=pflash,format=raw,readonly=on,file=${_currdir}/ovmf/vars.fd"

  -device "virtio-net-pci,netdev=net0"
  -netdev "user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::50000-:50000,hostfwd=tcp::50001-:50001"

  -device virtio-gpu -vga virtio

  -device "pcie-root-port,id=pcie_r0,bus=pcie.0,chassis=0,slot=0"
  -device "nvme,bootindex=1,drive=nvdisk0,serial=disk0,bus=pcie_r0"

  -smbios "type=1,serial=ds=nocloud-net;s=http://10.0.2.2:8100/"
)

_usage=$(cat <<EOF
Usage: qemu.sh [OPTIONS] DISKFILE

Start a QEMU virtual machine, optionally creating a disk image.

Arguments:
  DISKFILE                   Path to qcow2 disk image to attach to the VM.
                             If the file doesn't exist, it will be created.

Options:
  -h, --help                 Show this usage information.

  -s, --disk-size=DISKSIZE   Size of the created disk image.
                             Required if the disk image file doesn't exist,
                             and a backing file is not specified.
                             Examples: 500G, 2T
                             Env var: \$QEMUSH_DISK_SIZE

  -i, --iso=ISOFILE          Path to ISO file to attach to the VM and boot from.
                             Env var: \$QEMUSH_ISO

  -b, --backing=BACKINGFILE  Path to qcow2 disk image that should be the backing
                             file (i.e. "parent") of the main DISKFILE.
                             Env var: \$QEMUSH_BACKING

  -d, --daemonize            Run VM without a display, in the background.
                             Env var: \$QEMUSH_DAEMONIZE

Any leftover arguments will be passed to the QEMU command.

Examples:
- Boot an existing disk image in the foreground:
  qemu.sh "img/guix-\$(date '+%Y%m%d').qcow2"

- Create a 2T disk image, and boot an existing ISO file in the background:
  qemu.sh --iso="img/guix-install-\$(date '+%Y%m%d').iso" \\
    --disk-size=2T --daemonize "img/guix-\$(date '+%Y%m%d').qcow2"

- Create and boot a disk image backed by another image in the foreground:
  qemu.sh --backing="img/guix-\$(date '+%Y%m%d')-pre_setup.qcow2" \\
    "img/guix-\$(date '+%Y%m%d').qcow2"

NOTE: To avoid ambiguity, values for both long and short options should be
specified using an equals sign and no space. I.e. --option=4 and -o=4 instead of
--option 4 and -o 4.
EOF
)

usage() {
  printf "%s\n" "$_usage"
  exit "$1"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case $1 in
      -b=*|--backing=*)    backing_file="${1##*=}" ;;
      -d|--daemonize)      daemonize=1 ;;
      -i=*|--iso=*)        iso_file="${1##*=}" ;;
      -s=*|--disk-size=*)  disk_size="${1##*=}" ;;
      -h|--help)           usage 0 ;;
      # Gather leftover options for QEMU
      -*) _opts+=("$1")  ;;
      *)  disk_file="$1" ;;
    esac
    shift
  done
}

validate_args() {
  if [ -z "$disk_file" ]; then
    err "must provide a path to a qcow2 disk image"
    usage 1
  fi

  if [ ! -r "$disk_file" ] && [ -z "$backing_file" ] && [ -z "$disk_size" ]; then
    err "must provide a disk size to create a qcow2 disk image"
    usage 1
  fi

  if [ -n "$backing_file" ] && [ ! -r "$backing_file" ]; then
    quit "backing disk image file doesn't exist: ${backing_file}"
  fi

  if [ -n "$iso_file" ] && [ ! -r "$iso_file" ]; then
    quit "ISO file doesn't exist: ${iso_file}"
  fi
}

check_deps() {
  _qemu="$(command -v "$_qemu" || quit "${_qemu} not found")"
  _qemu_img="$(command -v "$_qemu_img" || quit "${_qemu_img} not found")"
}

load_env() {
  backing_file="${QEMUSH_BACKING:-}"
  daemonize="${QEMUSH_DAEMONIZE:-0}"
  disk_size="${QEMUSH_DISK_SIZE:-}"
  iso_file="${QEMUSH_ISO:-}"
}

create_img() {
  local _file="$1"
  local _backing="${2:-}"

  local _opts=(create -f qcow2)

  if [ -n "$_backing" ]; then
    # Convert to absolute path to avoid weird handling of relative paths by qemu-img.
    # I.e. if the path is relative, qemu-img expects it to be relative to the new
    # image file, not to the current working directory.
    local _backing_abs="$(realpath -m "$_backing")"
    _opts+=(-b "$_backing_abs" -F qcow2 "$_file")
    log "Creating disk image '${_file}' backed by '${_backing}'"
  else
    log "Creating ${disk_size} disk image '${_file}'"
    _opts+=("$_file" "$disk_size")
  fi

  "$_qemu_img" "${_opts[@]}"
}

run() {
  __log_ts="1"

  if [ ! -r "$disk_file" ]; then
    create_img "$disk_file" "$backing_file"
  fi

  _opts+=(-drive "id=nvdisk0,file=${disk_file},format=qcow2,if=none,media=disk,cache=none,aio=native,discard=unmap")

  local _log_msg="Starting VM with disk '${disk_file}'"
  if [ -n "$iso_file" ]; then
    _opts+=(
      -device "ahci,id=ahci0"
      -device "ide-cd,bootindex=0,drive=cdrom0,bus=ahci0.0"
      -drive "id=cdrom0,file=${iso_file},format=raw,if=none,media=cdrom,readonly=on"
    )
    _log_msg="${_log_msg} and ISO '${iso_file}'"
  fi

  if [ "$daemonize" -eq 1 ]; then
    _opts+=(-display none -daemonize)
  fi

  log "${_log_msg}"
  "$_qemu" "${_opts[@]}"
}

check_deps
load_env
parse_args "$@"
validate_args
run
