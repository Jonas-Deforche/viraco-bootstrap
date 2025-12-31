#!/usr/bin/env bash
set -euo pipefail

# =========================
# Viraco Control Node Bootstrap (ALL-IN-ONE)
# =========================
# Run:
#   sudo bash /root/bootstrap_control_node_allinone.sh
#
# Optional env overrides:
#   CTRL_USER=deploy
#   KEY_DIR=/root/bootstrap-secrets
#   REPO_URL=git@github.com:Jonas-Deforche/viraco-infra.git
#   REPO_BRANCH=main
#   DEST_DIR=/opt/viraco-infra
#   ANSIBLE_VENV=/opt/ansible-venv
#   TEST_LIMIT=prod

LOG_PREFIX="${LOG_PREFIX:-[bootstrap]}"
log(){ echo "${LOG_PREFIX} $*"; }
warn(){ echo "${LOG_PREFIX} WARN: $*" >&2; }
err(){ echo "${LOG_PREFIX} ERROR: $*" >&2; }

CTRL_USER="${CTRL_USER:-deploy}"
KEY_DIR="${KEY_DIR:-/root/bootstrap-secrets}"

REPO_URL="${REPO_URL:-git@github.com:Jonas-Deforche/viraco-infra.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
DEST_DIR="${DEST_DIR:-/opt/viraco-infra}"

ANSIBLE_VENV="${ANSIBLE_VENV:-/opt/ansible-venv}"
TEST_LIMIT="${TEST_LIMIT:-prod}"

LOCK_FILE="${LOCK_FILE:-/var/lock/viraco-controlnode-bootstrap.lock}"

require_root() {
  [ "$(id -u)" -eq 0 ] || { err "Run as root (sudo)"; exit 1; }
}

acquire_lock() {
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    err "Another bootstrap is running (lock: $LOCK_FILE)"
    exit 1
  fi
  log "Lock acquired: $LOCK_FILE"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

apt_update() {
  export DEBIAN_FRONTEND=noninteractive
  local tries=5 delay=3
  for i in $(seq 1 $tries); do
    log "apt-get update (try $i/$tries)"
    if apt-get -y update; then return 0; fi
    warn "apt-get update failed, retry in ${delay}s..."
    sleep "$delay"
    delay=$((delay*2))
  done
  err "apt-get update failed after retries"
  return 1
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  log "apt-get install: $*"
  apt-get -y install --no-install-recommends "$@"
}

ensure_packages() {
  if have_cmd apt-get; then
    apt_update
    apt_install \
      git openssh-client ca-certificates \
      python3 python3-pip python3-venv python3-dev build-essential \
      rsync jq nano
  else
    err "This all-in-one script currently supports Debian/Ubuntu with apt-get."
    err "Install git/ssh/python3/pip/venv/build tools manually, then re-run."
    exit 1
  fi
}

ensure_user() {
  if id -u "${CTRL_USER}" >/dev/null 2>&1; then
    log "User exists: ${CTRL_USER}"
  else
    log "Creating user: ${CTRL_USER}"
    useradd -m -s /bin/bash "${CTRL_USER}"
    usermod -aG sudo "${CTRL_USER}" >/dev/null 2>&1 || true
  fi
}

ensure_nopasswd_sudo_controlnode() {
  local f="/etc/sudoers.d/${CTRL_USER}"
  if [ -f "$f" ] && grep -q 'NOPASSWD:ALL' "$f"; then
    log "NOPASSWD sudo already configured for ${CTRL_USER} (control node)"
    return 0
  fi
  log "Configuring passwordless sudo for ${CTRL_USER} on control node"
  printf "%s ALL=(ALL) NOPASSWD:ALL\n" "${CTRL_USER}" > "$f"
  chmod 440 "$f"
  visudo -c >/dev/null
}

# --- Secrets staging + paste ---
ensure_keydir_empty_files() {
  mkdir -p "$KEY_DIR"
  chmod 700 "$KEY_DIR"
  # Create empty files if missing
  for f in id_ed25519_servers id_ed25519_github vault_pass.txt; do
    if [ ! -f "$KEY_DIR/$f" ]; then
      : > "$KEY_DIR/$f"
      chmod 600 "$KEY_DIR/$f"
      log "Prepared empty: $KEY_DIR/$f"
    fi
  done
}

paste_secrets_interactive() {
  log "You will now paste secrets from Bitwarden."
  log "IMPORTANT: paste ONLY the key content, no extra header lines."
  log "Files:"
  log "  1) $KEY_DIR/id_ed25519_servers"
  log "  2) $KEY_DIR/id_ed25519_github"
  log "  3) $KEY_DIR/vault_pass.txt (vault password, preferably single line)"
  echo

  log "Opening nano for id_ed25519_servers (paste private key, save, exit)"
  nano "$KEY_DIR/id_ed25519_servers"

  log "Opening nano for id_ed25519_github (paste private key, save, exit)"
  nano "$KEY_DIR/id_ed25519_github"

  log "Opening nano for vault_pass.txt (paste vault pass, save, exit)"
  nano "$KEY_DIR/vault_pass.txt"
}

validate_secrets() {
  log "Validating private keys with ssh-keygen..."
  ssh-keygen -y -f "$KEY_DIR/id_ed25519_servers" >/dev/null
  ssh-keygen -y -f "$KEY_DIR/id_ed25519_github" >/dev/null
  log "Keys valid."
}

# --- Install secrets to CTRL_USER ---
home_dir() { getent passwd "${CTRL_USER}" | cut -d: -f6; }

install_key_to_user() {
  local src="$1" dest="$2" h
  h="$(home_dir)"
  install -d -m 0700 -o "${CTRL_USER}" -g "${CTRL_USER}" "${h}/.ssh"
  install -m 0600 -o "${CTRL_USER}" -g "${CTRL_USER}" "$src" "${h}/.ssh/${dest}"
}

write_ssh_config() {
  local h; h="$(home_dir)"
  cat > "${h}/.ssh/config" <<'EOF'
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519_github
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

Host *
  IdentityFile ~/.ssh/id_ed25519_servers
  IdentitiesOnly yes
  ServerAliveInterval 30
  ServerAliveCountMax 4
EOF
  chown "${CTRL_USER}:${CTRL_USER}" "${h}/.ssh/config"
  chmod 600 "${h}/.ssh/config"
}

prime_known_hosts() {
  local h; h="$(home_dir)"
  touch "${h}/.ssh/known_hosts"
  chown "${CTRL_USER}:${CTRL_USER}" "${h}/.ssh/known_hosts"
  chmod 600 "${h}/.ssh/known_hosts"
  ssh-keyscan -t rsa,ecdsa,ed25519 github.com 2>/dev/null | \
    sudo -u "${CTRL_USER}" -H bash -lc "cat >> ~/.ssh/known_hosts" || true
}

install_vault_pass_to_user() {
  local h; h="$(home_dir)"
  install -d -m 0700 -o "${CTRL_USER}" -g "${CTRL_USER}" "${h}/.ansible"
  install -m 0600 -o "${CTRL_USER}" -g "${CTRL_USER}" "$KEY_DIR/vault_pass.txt" "${h}/.ansible/vault_pass.txt"
}

restore_secrets_to_user() {
  log "Installing SSH keys + config for ${CTRL_USER}"
  install_key_to_user "$KEY_DIR/id_ed25519_servers" "id_ed25519_servers"
  install_key_to_user "$KEY_DIR/id_ed25519_github"  "id_ed25519_github"
  write_ssh_config
  prime_known_hosts
  install_vault_pass_to_user
  log "Secrets installed to /home/${CTRL_USER}"
}

run_as_user() {
  sudo -u "$CTRL_USER" -H bash -lc "$*"
}

github_ssh_ok() {
  run_as_user "ssh -T git@github.com 2>&1 | grep -qi 'successfully authenticated\|Hi '"
}

ensure_dest_dir() {
  mkdir -p "$DEST_DIR"
  chown -R "${CTRL_USER}:${CTRL_USER}" "$DEST_DIR" || true
}

clone_or_update_repo() {
  # Clean non-git leftovers
  if [ -d "$DEST_DIR" ] && [ ! -d "$DEST_DIR/.git" ]; then
    if [ "$(ls -A "$DEST_DIR" 2>/dev/null | wc -l)" -gt 0 ]; then
      warn "Non-git contents in $DEST_DIR. Removing."
      rm -rf "$DEST_DIR"
      ensure_dest_dir
    fi
  fi

  if [ -d "$DEST_DIR/.git" ]; then
    log "Repo exists; updating"
    run_as_user "cd '$DEST_DIR' && git fetch --all --prune && git checkout '$REPO_BRANCH' && git pull --ff-only"
    return 0
  fi

  log "Cloning repo to $DEST_DIR"
  if ! github_ssh_ok; then
    err "GitHub SSH auth not working for ${CTRL_USER}."
    run_as_user "ssh -vT git@github.com" || true
    exit 1
  fi

  run_as_user "GIT_SSH_COMMAND='ssh -F ~/.ssh/config' git clone --branch '$REPO_BRANCH' '$REPO_URL' '$DEST_DIR'"
}

fix_ansible_cfg() {
  local cfg="$DEST_DIR/ansible.cfg"
  if [ ! -f "$cfg" ]; then
    log "No ansible.cfg in repo; skipping"
    return 0
  fi

  log "Ensuring vault_password_file = ~/.ansible/vault_pass.txt"
  if grep -qE '^\s*vault_password_file\s*=' "$cfg"; then
    sed -i 's#^\s*vault_password_file\s*=.*#vault_password_file = ~/.ansible/vault_pass.txt#' "$cfg"
  else
    if grep -q '^\[defaults\]' "$cfg"; then
      awk '
        BEGIN{added=0}
        /^\[defaults\]/{print; if(!added){print "vault_password_file = ~/.ansible/vault_pass.txt"; added=1; next}}
        {print}
      ' "$cfg" > "$cfg.tmp" && mv "$cfg.tmp" "$cfg"
    else
      printf "\n[defaults]\nvault_password_file = ~/.ansible/vault_pass.txt\n" >> "$cfg"
    fi
  fi
  chown "${CTRL_USER}:${CTRL_USER}" "$cfg" || true
}

install_ansible_venv() {
  log "Installing Ansible in venv: $ANSIBLE_VENV"
  python3 -m venv "$ANSIBLE_VENV"
  "$ANSIBLE_VENV/bin/python" -m pip install --upgrade pip wheel >/dev/null
  "$ANSIBLE_VENV/bin/pip" install "ansible>=9,<11" ansible-lint >/dev/null

  ln -sf "$ANSIBLE_VENV/bin/ansible" /usr/local/bin/ansible || true
  ln -sf "$ANSIBLE_VENV/bin/ansible-playbook" /usr/local/bin/ansible-playbook || true
  ln -sf "$ANSIBLE_VENV/bin/ansible-galaxy" /usr/local/bin/ansible-galaxy || true
}

tests() {
  log "Test: GitHub SSH"
  run_as_user "ssh -T git@github.com || true"

  if [ -f "$DEST_DIR/inventories/production/inventory.yml" ]; then
    log "Test: ansible --version"
    /usr/local/bin/ansible --version || true

    log "Test: ansible ping (limit=$TEST_LIMIT)"
    if ! run_as_user "cd '$DEST_DIR' && ansible -i inventories/production/inventory.yml '$TEST_LIMIT' -m ping"; then
      warn "Ping failed for limit='$TEST_LIMIT' (maybe group doesn't exist). Trying 'all'..."
      run_as_user "cd '$DEST_DIR' && ansible -i inventories/production/inventory.yml all -m ping" || true
    fi
  else
    warn "No inventories/production/inventory.yml found; skipping ansible ping"
  fi
}

main() {
  require_root
  acquire_lock

  ensure_packages
  ensure_user
  ensure_nopasswd_sudo_controlnode

  ensure_keydir_empty_files

  # Always give you a chance to paste/update keys at runtime.
  paste_secrets_interactive

  validate_secrets
  restore_secrets_to_user

  ensure_dest_dir
  clone_or_update_repo
  fix_ansible_cfg
  install_ansible_venv
  tests

  log "Done."
}

main "$@"
