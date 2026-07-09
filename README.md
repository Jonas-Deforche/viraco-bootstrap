# Viraco Bootstrap (Public)

> README laatst gesynct: 2026-07-09 (commit 89e0fc7)

This repository contains **NO secrets**.  
It provides bootstrap scripts to prepare infrastructure nodes in a **clean, reproducible way**.

The goal:
- Any VM can be rebuilt from scratch
- Bootstrap is cloud-agnostic (GCP, Hetzner, bare metal, ...)
- Private infrastructure remains private

---

## Repository structure

```
viraco-bootstrap/
├── control-node/
│   └── bootstrap_control_node.sh
├── target-node/
│   └── bootstrap_target_node.sh
└── windows-node/
    ├── bootstrap/        # numbered .ps1 fragments (00-common, 10-winrm, ...)
    │                     # + helper installers (installSteam, sdinstaller.ps1)
    │                     # + `set aan` snippet to unblock & run the fragments
    └── config/
        └── node.json     # per-node settings (hostname, WireGuard, Splashtop, ...)
```

### Terminology
- **Control node**  
  The machine where Ansible runs (CI / automation / infra controller)
- **Target node**  
  Any Linux machine managed *by* Ansible (web, db, game servers, etc.)
- **Windows node**  
  A Windows sim-PC. Bootstrapped via PowerShell fragments in `windows-node/bootstrap/`.

This follows standard Ansible terminology and avoids cloud/vendor lock-in.

---

## 0) Prerequisites (fresh VM)

If the VM is brand new, install the basics first.

### Debian / Ubuntu
```bash
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl nano
```

---

## 1) Bootstrap a TARGET node (managed server)

This script:
- Creates the `deploy` user
- Installs SSH **public keys**
- Enables passwordless sudo for `deploy`
- Ensures SSH is running
- Installs python3 (required for Ansible)

### One command to paste on a TARGET node
```bash
sudo apt-get update -y && sudo apt-get install -y ca-certificates curl nano && \
sudo curl -fsSL https://raw.githubusercontent.com/Jonas-Deforche/viraco-bootstrap/main/target-node/bootstrap_target_node.sh -o /root/bootstrap_target_node.sh && \
sudo chmod +x /root/bootstrap_target_node.sh && \
sudo /root/bootstrap_target_node.sh
```

What happens next:
- Nano opens
- Paste **SSH PUBLIC keys** (one per line)
- Save & exit
- Server is now ready for Ansible

### Public key format
```
ssh-ed25519 AAAA... comment
```

### Optional flags
```bash
sudo ./bootstrap_target_node.sh --key-file /root/bootstrap/deploy_keys.txt
sudo ./bootstrap_target_node.sh --key "ssh-ed25519 AAAA... jonas@laptop"
sudo ./bootstrap_target_node.sh --user deploy --no-python --no-sshd
```
The script supports apt, dnf, yum and apk based distros.

---

## 2) Bootstrap the CONTROL node (Ansible controller)

This script:
- Installs required system packages
- Creates `deploy` user + passwordless sudo
- Prompts (via nano) to paste:
  - private server SSH key
  - private GitHub SSH key
  - Ansible vault password
- Clones the **private** infrastructure repository via SSH
- Installs Ansible in a virtualenv
- Runs basic connectivity tests

### One command to paste on the CONTROL node
```bash
sudo apt-get update -y && sudo apt-get install -y ca-certificates curl nano && \
sudo curl -fsSL https://raw.githubusercontent.com/Jonas-Deforche/viraco-bootstrap/main/control-node/bootstrap_control_node.sh -o /root/bootstrap_control_node.sh && \
sudo chmod +x /root/bootstrap_control_node.sh && \
sudo /root/bootstrap_control_node.sh
```

Defaults: the private repo is cloned to `/opt/viraco-infra`, Ansible (`>=9,<11`) is installed in `/opt/ansible-venv` and symlinked into `/usr/local/bin`.

### Optional overrides
```bash
sudo REPO_URL=git@github.com:Jonas-Deforche/viraco-infra.git /root/bootstrap_control_node.sh
sudo TEST_LIMIT=prod /root/bootstrap_control_node.sh
# Also available: CTRL_USER, KEY_DIR, REPO_BRANCH, DEST_DIR, ANSIBLE_VENV
```

---

## 3) Bootstrap a WINDOWS node (sim-PC)

Not a single script but PowerShell **fragments**, run manually as Administrator:

1. Copy `windows-node/bootstrap/` to `C:\Viraco\bootstrap` and `windows-node/config/node.json` to `C:\Viraco\config\node.json`
2. Edit `node.json` (hostname, WireGuard tunnel + config path, Splashtop installer URL, RustDesk URL, `steam` flag)
3. Unblock and run the fragments (see the `set aan` snippet):
```powershell
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
Get-ChildItem C:\Viraco\bootstrap -Filter *.ps1 | Unblock-File
powershell.exe -ExecutionPolicy Bypass -File C:\Viraco\bootstrap\10-winrm.ps1
```

Fragments (each sources `00-common.ps1` for shared helpers and reads `node.json`):
- `10-winrm.ps1` — enable WinRM
- `20-wireguard.ps1` — install WireGuard tunnel
- `30-splashtop.ps1` / `35-splash.ps1` — silent install Splashtop Streamer (DEPLOY installer), optional rename + reboot
- `60-power.ps1` — disable standby / monitor timeout / hibernate
- `90-tag.ps1` — tag the node
- `installSteam` / `sdinstaller.ps1` — helper installers for Steam and SD Launcher

---

## 4) Secrets handling (important)

### Target nodes
- Only **public** SSH keys are pasted
- No secrets are stored

### Control node
You will paste **private secrets manually** from Bitwarden:
- `id_ed25519_servers`
- `id_ed25519_github`
- `vault_pass.txt`

They are installed securely under:
```
/home/deploy/.ssh
/home/deploy/.ansible
```

No secrets are ever committed to GitHub.

---

## 5) Design principles

- Bootstrap repo is **public**
- Infrastructure repo is **private**
- No tokens, no passwords in scripts
- Cloud-agnostic
- Fully reproducible

> If a VM is destroyed, you are back online in minutes.

---

## 6) Typical workflow

1. Create VM
2. Run **target-node bootstrap**
3. (Once) bootstrap the **control node**
4. Manage everything via Ansible

That’s it.
