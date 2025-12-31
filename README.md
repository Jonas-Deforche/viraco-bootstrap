# Viraco Bootstrap (Public)

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
└── bootstrap/
    ├── control-node/
    │   └── bootstrap_control_node.sh
    └── target-node/
        └── bootstrap_target_node.sh
```

### Terminology
- **Control node**  
  The machine where Ansible runs (CI / automation / infra controller)
- **Target node**  
  Any machine managed *by* Ansible (web, db, game servers, etc.)

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

### Optional overrides
```bash
sudo REPO_URL=git@github.com:Jonas-Deforche/viraco-infra.git /root/bootstrap_control_node.sh
sudo TEST_LIMIT=prod /root/bootstrap_control_node.sh
```

---

## 3) Secrets handling (important)

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

## 4) Design principles

- Bootstrap repo is **public**
- Infrastructure repo is **private**
- No tokens, no passwords in scripts
- Cloud-agnostic
- Fully reproducible

> If a VM is destroyed, you are back online in minutes.

---

## 5) Typical workflow

1. Create VM
2. Run **target-node bootstrap**
3. (Once) bootstrap the **control node**
4. Manage everything via Ansible

That’s it.
