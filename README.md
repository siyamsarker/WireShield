<div align="center">

# WireShield

Secure, modern, one-command WireGuard VPN installer and manager for Linux.

<sub>Simple to use. Sensible defaults. Production-friendly.</sub>

</div>

## Overview

WireShield is a single-file bash tool that installs and manages a [WireGuard](https://www.wireguard.com/) VPN server in minutes. It sets up a secure tunnel so clients can route traffic through your server (full-tunnel or split-tunnel), with automatic firewalling and IPv4/IPv6 support.

Highlights:


## Table of contents

- [Overview](#overview)
- [Supported platforms](#supported-platforms)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Architecture](#architecture)
- [Configuration details](#configuration-details)
- [Security considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [FAQ](#faq)
- [Contributors](#contributors)
- [License](#license)
- [Acknowledgements](#acknowledgements)
## Supported platforms

WireShield supports these Linux distributions out of the box:

- AlmaLinux ≥ 8
## Quick start

Download and run the script as root (or with sudo):

```bash
wget https://raw.githubusercontent.com/siyamsarker/WireShield/master/wireshield.sh -O wireshield.sh
chmod +x wireshield.sh
sudo ./wireshield.sh
```

You’ll be asked a few questions (address/hostname, public NIC, wg interface, IPs, port, DNS, AllowedIPs). A summary is shown at the end—confirm to proceed. WireShield will install WireGuard, configure the server, enable forwarding, set firewall rules, and create your first client.

## Usage

After installation, rerun the script anytime to open the interactive menu:

```
1) Add a new client
2) List clients
3) Show QR for a client
4) Revoke existing client
5) Show server status
6) Restart WireGuard
7) Backup configuration
8) Uninstall WireGuard
9) Exit
```

Notes:

- If `whiptail` is present, you’ll get a dialog-based UI; otherwise, a clean CLI menu.
## Configuration details


```mermaid
flowchart LR
  C[WireGuard Client(s)] -- Encrypted UDP --> S[WireShield Server]
  S --> I[(Internet)]
  subgraph Server
    S -- wg-quick@<iface> --> WG[(wg/wg-quick)]
    S -- iptables/firewalld --> FW[(Firewall & NAT)]
    S -- /etc/wireguard --> CFG[(Configs)]
  end
```

Install flow (high level):

```mermaid
sequenceDiagram
  participant U as User
  participant WS as WireShield Script
  participant PM as Package Manager
  participant WG as wg-quick

  U->>WS: Run wireshield.sh
  WS->>WS: Ask questions + validate + confirm
  WS->>PM: Install wireguard tools and deps
  WS->>WS: Write /etc/wireguard configs
  WS->>WG: Start wg-quick@<iface>
  WS->>U: Show success, create first client
```
- Files and paths
  - Server config: `/etc/wireguard/<interface>.conf` (0600)
  - Global params: `/etc/wireguard/params`
  - Sysctl settings: `/etc/sysctl.d/wg.conf`

- Firewall rules
  - firewalld: zones and rich rules for NAT/masquerade are applied automatically
  - iptables: INPUT/FORWARD/POSTROUTING rules for the selected UDP port and interface
- Client routing (AllowedIPs)
  - Default is `0.0.0.0/0,::/0` (full tunnel). Set a narrower range for split tunnel.

  - Specify preferred DNS resolvers during install; clients inherit these.

  - You can set a custom MTU in client configs if needed (comment provided in file).


- Runs with root privileges by design (network stack, firewall, sysctl, and `/etc/wireguard`).
- Generates fresh key pairs and pre-shared keys per client.
- Restricts config permissions to 0600.
- Port and connectivity
  - Ensure the chosen UDP port is open in provider firewalls/security groups and any local firewall.
  - UFW example:
    sudo ufw allow <your_port>/udp
    sudo ufw reload
    ```

- Service status and peers
  - Check service status:
    ```bash
    ```
  - Show live peers/handshakes:
    ```bash
    sudo wg show
    ```

- Kernel and module
  - WireGuard is built into Linux 5.6+. On older kernels the module is installed.
  - Verify:
    uname -r
    wg --version
    ```
  - If you see “Cannot find device wg0”, reboot the server first.

- No internet on client
  - Reboot the server after kernel or package updates.
  - Confirm forwarding:
    sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
    ```
  - Try setting a lower MTU (e.g., 1420) in the client config if you suspect fragmentation.

- QR code not shown
  - Ensure `qrencode` is installed (the installer attempts this automatically when available).


From the menu, choose “Uninstall WireGuard”. The script will stop the service, remove packages and `/etc/wireguard`, reload sysctl, and remove detected client `.conf` files from `/root` and `/home`.
<details>
<summary>More tips</summary>

- Endpoint hostname vs IP
  - You can use a hostname for the public address; ensure DNS resolves correctly from clients.

- Double NAT scenarios
  - If your server sits behind NAT, ensure UDP port forwarding is configured on the upstream router.

- Split tunnel examples
  - For office subnets only, set AllowedIPs to e.g. `10.0.0.0/8,192.168.0.0/16` instead of default `0.0.0.0/0,::/0`.

</details>

## FAQ

- Can I reuse a client name after revoking?
  - Yes. Revoking removes the peer and its `.conf` files, allowing name reuse.

- Where are client configs saved?

- Do I need IPv6?

## License
Licensed under the [MIT License](LICENSE).

## Contributors

Thanks goes to everyone who has contributed. Want to be part of it? Star the repo, open issues, and send PRs!

[![Contributors](https://contrib.rocks/image?repo=siyamsarker/WireShield)](https://github.com/siyamsarker/WireShield/graphs/contributors)
## Acknowledgements

WireShield was inspired by the simplicity-first approach of WireGuard tooling and community best practices for secure VPN setups.


