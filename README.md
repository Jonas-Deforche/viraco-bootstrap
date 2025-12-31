# Viraco Bootstrap (Public)

This repo contains **no secrets**.
It only provides bootstrap scripts to quickly prepare:
- **Target nodes** (servers that Ansible will manage)
- The **Control node** (your Ansible controller / CI node)

After bootstrapping, you can safely clone your **private** infra repo via SSH.

---

## 0) Quick download helper (optional)

If a VM is super fresh, install curl first:

### Debian/Ubuntu
```bash
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl
