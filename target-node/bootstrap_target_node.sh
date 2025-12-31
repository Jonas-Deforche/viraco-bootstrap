#!/usr/bin/env bash
# Viraco target pre-bootstrap (production-ish)
# - Creates/ensures deploy user
# - Lets you paste deploy public keys via nano at runtime (or via --key-file / --key)
# - Installs SSH public keys into authorized_keys (no duplicates)
# - Configures passwordless sudo safely (validated with visudo)
# - Ensures SSH service is running (best-effort)
# - Installs python3 if missing (recommended for Ansible)
#
# Usage examples:
#   sudo ./pre_bootstrap.sh
#   sudo ./pre_bootstrap.sh --key-file /root/bootstrap/deploy_keys.txt
#   sudo ./pre_bootstrap.sh --user deploy --key-file /root/bootstrap/deploy_keys.txt
#   sudo ./pre_bootstrap.sh --key "ssh-ed25519 AAAA... jonas@laptop"
#   sudo ./pre_bootstrap.sh --no-python
#   sudo ./pre_bootstrap.sh --no-sshd
#
# Keyfile format:
#   - one public key per line
#   - empty lines allowed
#   - lines starting with # are ignored

set -euo pipefail

DEPLOY_USER="deploy"
KEY_FILE=""
INSTALL_PYTHON=1
ENSURE_SSHD=1

# If KEY_FILE not provided, we'll open nano here:
DEFAULT_KEY_FILE="/root/bootstrap/deploy_keys.txt"

DEFAULT_KEYS=()   # optional hardcoded defaults (kept empty)

SUDOERS_FILE=""

log() { echo "[prebootstrap] $*"; }
warn() { echo "[prebootstrap] WARN: $*" >&2; }
err() { echo "[prebootstrap] ERROR: $*" >&2; }

usage() {
  cat <<'EOF'
Usage:
  pre_bootstrap.sh [options]

Options:
  --user <name>       Deploy user (default: deploy)
  --key-file <path>   File containing SSH public keys (one per line)
                      If omitted, the script will open nano so you can paste keys.
  --key <pubkey>      Add one SSH public key (can be used multiple times)
  --no-python         Skip python3 install
  --no-sshd           Skip enabling/starting ssh/sshd service
  -h, --help          Show help

Examples:
  sudo ./pre_bootstrap.sh
  sudo ./pre_bootstrap.sh --key-file /root/bootstrap/deploy_keys.txt
  sudo ./pre_bootstrap.sh --key "ssh-ed25519 AAAA... jonas@laptop"
EOF
}

DEPLOY_KEYS=()

parse_args() {
  while [ "${#}" -gt 0 ]; do
    case "$1" in
      --user)
        DEPLOY_USER="${2:-}"
        [ -n "${DEPLOY_USER}" ] || { err "Missing value for --user"; exit 1; }
        shift 2
        ;;
      --key-file)
        KEY_FILE="${2:-}"
        [ -n "${KEY_FILE}" ] || { err "Missing value for --key-file"; exit 1; }
        shift 2
        ;;
      --key)
        local k="${2:-}"
        [ -n "${k}" ] || { err "Missing value for --key"; exit 1; }
        DEPLOY_KEYS+=("${k}")
        shift 2
        ;;
      --no-python)
        INSTALL_PYTHON=0
        shift
        ;;
      --no-sshd)
        ENSURE_SSHD=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "Unknown arg: $1"
        usage
        exit 1
        ;;
    esac
  done
}

SUDO="sudo"
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
fi

require_root_or_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    return 0
  fi
  err "This script needs root (or sudo)."
  exit 1
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v apk >/dev/null 2>&1; then
    echo "apk"
  else
    echo "unknown"
  fi
}

install_packages_if_needed() {
  # We want nano (for interactive paste), openssh-server (sometimes missing), and python3 if missing.
  local pm
  pm="$(detect_pkg_mgr)"

  case "${pm}" in
    apt)
      ${SUDO} apt-get update -y
      # nano + ssh server are safe on most targets; python is installed later if missing
      ${SUDO} apt-get install -y nano openssh-server ca-certificates >/dev/null 2>&1 || true
      ;;
    dnf)
      ${SUDO} dnf install -y nano openssh-server ca-certificates >/dev/null 2>&1 || true
      ;;
    yum)
      ${SUDO} yum install -y nano openssh-server ca-certificates >/dev/null 2>&1 || true
      ;;
    apk)
      ${SUDO} apk add --no-cache nano openssh ca-certificates >/dev/null 2>&1 || true
      ;;
    *)
      warn "Unknown package manager; cannot ensure nano/openssh-server. If nano is missing, provide --key-file."
      ;;
  esac
}

install_python3_if_missing() {
  [ "${INSTALL_PYTHON}" -eq 1 ] || { log "Skipping python3 install (--no-python)"; return 0; }

  if command -v python3 >/dev/null 2>&1; then
    log "python3 already installed"
    return 0
  fi

  local pm
  pm="$(detect_pkg_mgr)"
  log "python3 missing; installing via package manager: ${pm}"

  case "${pm}" in
    apt)
      ${SUDO} apt-get update -y
      ${SUDO} apt-get install -y python3 python3-venv python3-apt >/dev/null 2>&1 || ${SUDO} apt-get install -y python3
      ;;
    dnf)
      ${SUDO} dnf install -y python3
      ;;
    yum)
      ${SUDO} yum install -y python3
      ;;
    apk)
      ${SUDO} apk add --no-cache python3
      ;;
    *)
      warn "No supported package manager found; skipping python3 install"
      ;;
  esac
}

ensure_deploy_user() {
  if id -u "${DEPLOY_USER}" >/dev/null 2>&1; then
    log "User '${DEPLOY_USER}' exists"
  else
    log "Creating user '${DEPLOY_USER}'"
    ${SUDO} useradd -m -s /bin/bash "${DEPLOY_USER}"
  fi
}

ensure_key_file_interactive() {
  # If user didn't provide --key-file, we open nano at DEFAULT_KEY_FILE
  if [ -n "${KEY_FILE}" ]; then
    return 0
  fi

  KEY_FILE="${DEFAULT_KEY_FILE}"
  log "No --key-file provided."
  log "Opening nano to paste SSH PUBLIC keys (one per line):"
  log "  ${KEY_FILE}"
  log "Tip: lines starting with # are ignored."

  ${SUDO} mkdir -p "$(dirname "${KEY_FILE}")"
  ${SUDO} touch "${KEY_FILE}"
  ${SUDO} chmod 600 "${KEY_FILE}"

  if command -v nano >/dev/null 2>&1; then
    nano "${KEY_FILE}"
  else
    err "nano is not installed and no --key-file was provided."
    err "Install nano or re-run with: --key-file <path>"
    exit 1
  fi
}

read_keys_from_file() {
  if [ -z "${KEY_FILE}" ]; then
    # allowed: we may have keys only via --key
    return 0
  fi
  [ -f "${KEY_FILE}" ] || { err "Key file not found: ${KEY_FILE}"; exit 1; }

  while IFS= read -r line || [ -n "$line" ]; do
    # trim
    line="${line#"${line%%[![:space:]]*}"}"   # ltrim
    line="${line%"${line##*[![:space:]]}"}"   # rtrim
    [ -z "${line}" ] && continue
    [[ "${line}" == \#* ]] && continue
    DEPLOY_KEYS+=("${line}")
  done < "${KEY_FILE}"
}

ensure_ssh_keys() {
  local home_dir ssh_dir auth_keys
  home_dir="$(${SUDO} getent passwd "${DEPLOY_USER}" | cut -d: -f6)"
  if [ -z "${home_dir}" ]; then
    err "Could not determine home directory for ${DEPLOY_USER}"
    exit 1
  fi

  ssh_dir="${home_dir}/.ssh"
  auth_keys="${ssh_dir}/authorized_keys"

  log "Ensuring ${ssh_dir} exists with correct perms"
  ${SUDO} install -d -m 0700 -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" "${ssh_dir}"

  log "Ensuring ${auth_keys} exists"
  ${SUDO} touch "${auth_keys}"
  ${SUDO} chown "${DEPLOY_USER}:${DEPLOY_USER}" "${auth_keys}"
  ${SUDO} chmod 600 "${auth_keys}"

  local added=0
  for k in "${DEPLOY_KEYS[@]}"; do
    [ -n "${k}" ] || continue
    # avoid duplicates
    if ${SUDO} -u "${DEPLOY_USER}" grep -qxF "${k}" "${auth_keys}"; then
      continue
    fi
    printf "%s\n" "${k}" | ${SUDO} tee -a "${auth_keys}" >/dev/null
    added=1
  done

  ${SUDO} chown "${DEPLOY_USER}:${DEPLOY_USER}" "${auth_keys}"
  ${SUDO} chmod 600 "${auth_keys}"

  if [ "${added}" -eq 1 ]; then
    log "SSH keys updated for ${DEPLOY_USER}"
  else
    log "SSH keys already present for ${DEPLOY_USER}"
  fi
}

ensure_passwordless_sudo() {
  SUDOERS_FILE="/etc/sudoers.d/${DEPLOY_USER}"
  local line="${DEPLOY_USER} ALL=(ALL) NOPASSWD:ALL"

  log "Ensuring sudoers file ${SUDOERS_FILE}"
  ${SUDO} install -m 0440 -o root -g root /dev/null "${SUDOERS_FILE}"
  printf "%s\n" "${line}" | ${SUDO} tee "${SUDOERS_FILE}" >/dev/null

  log "Validating sudoers"
  ${SUDO} visudo -cf "${SUDOERS_FILE}" >/dev/null
}

ensure_sshd_running() {
  [ "${ENSURE_SSHD}" -eq 1 ] || { log "Skipping ssh/sshd management (--no-sshd)"; return 0; }

  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not available; skipping ssh service management"
    return 0
  fi

  if ${SUDO} systemctl list-unit-files 2>/dev/null | grep -qE '^ssh\.service'; then
    log "Ensuring ssh service is enabled and running"
    ${SUDO} systemctl enable --now ssh >/dev/null 2>&1 || true
  elif ${SUDO} systemctl list-unit-files 2>/dev/null | grep -qE '^sshd\.service'; then
    log "Ensuring sshd service is enabled and running"
    ${SUDO} systemctl enable --now sshd >/dev/null 2>&1 || true
  else
    warn "systemd ssh/sshd service not found; skipping"
  fi
}

self_test() {
  log "Self-test: deploy user + passwordless sudo"
  ${SUDO} -u "${DEPLOY_USER}" -H bash -lc "whoami && sudo -n true && echo SUDO_OK"
  log "Done."
}

main() {
  parse_args "$@"
  require_root_or_sudo

  # Make sure nano/sshd exist when possible (helps interactive workflow)
  install_packages_if_needed

  # If no key-file was provided, open nano so you can paste keys.
  # (Still allows additional keys via --key)
  ensure_key_file_interactive

  # Load keys (from file + optional inline keys/defaults)
  read_keys_from_file
  if [ "${#DEFAULT_KEYS[@]}" -gt 0 ]; then
    DEPLOY_KEYS+=("${DEFAULT_KEYS[@]}")
  fi

  # De-duplicate keys in memory
  if [ "${#DEPLOY_KEYS[@]}" -gt 1 ]; then
    mapfile -t DEPLOY_KEYS < <(printf "%s\n" "${DEPLOY_KEYS[@]}" | awk '!seen[$0]++')
  fi

  if [ "${#DEPLOY_KEYS[@]}" -eq 0 ]; then
    err "No SSH keys provided. Paste at least one public key or use --key / --key-file."
    exit 1
  fi

  log "Starting pre-bootstrap (user=${DEPLOY_USER}, keyfile=${KEY_FILE:-<none>})"

  ensure_deploy_user
  ensure_ssh_keys
  ensure_passwordless_sudo
  ensure_sshd_running
  install_python3_if_missing
  self_test

  log "You should now be able to: ssh ${DEPLOY_USER}@<server-ip>"
}

main "$@"
