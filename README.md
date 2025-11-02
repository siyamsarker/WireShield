# WireShield

**WireShield is a bash script that aims to setup a [WireGuard](https://www.wireguard.com/) VPN on a Linux server, as easily as possible!**

WireGuard is a point-to-point VPN that can be used in different ways. Here, we mean a VPN as in: the client will forward all its traffic through an encrypted tunnel to the server.
The server will apply NAT to the client's traffic so it will appear as if the client is browsing the web with the server's IP.

The script supports both IPv4 and IPv6. It automatically detects your kernel version and installs the appropriate WireGuard packages. For Linux kernel 5.6+, WireGuard is built-in. For older kernels, the necessary modules are installed.

Please check the [issues](https://github.com/siyamsarker/WireShield/issues) for ongoing development, bugs and planned features! You might also want to check the [discussions](https://github.com/siyamsarker/WireShield/discussions) for help.

## Features

- **Latest WireGuard Support**: Automatically detects kernel version and installs appropriate WireGuard packages
  - Linux kernel 5.6+ uses built-in WireGuard
  - Older kernels get WireGuard kernel module installed
- **Easy Installation**: Interactive setup with sensible defaults
- **Dual Stack**: Full IPv4 and IPv6 support
- **Security First**: 
  - Pre-shared keys for additional quantum-resistant security
  - Automatic firewall configuration (iptables/firewalld)
  - Secure file permissions on all configuration files
- **Client Management**: Easy add, list, and revoke client configurations
- **QR Code Generation**: Instant QR codes for mobile device setup
- **Multiple DNS Options**: Configure custom DNS resolvers for clients
- **Flexible Routing**: Configurable AllowedIPs for full tunnel or split tunnel VPN
- **NAT Traversal**: Built-in support with PersistentKeepalive option
- **Clean Uninstall**: Complete removal option with all configurations

## Requirements

Supported distributions:

- AlmaLinux >= 8
- Alpine Linux
- Arch Linux
- CentOS Stream >= 8
- Debian >= 10
- Fedora >= 32
- Oracle Linux
- Rocky Linux >= 8
- Ubuntu >= 18.04

## Usage

Download and execute the script. Answer the questions asked by the script and it will take care of the rest.

```bash
curl -O https://raw.githubusercontent.com/siyamsarker/WireShield/master/wireshield.sh
chmod +x wireshield.sh
./wireshield.sh
```

It will install WireGuard (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.

Run the script again to add or remove clients!

### Quick Start

First time installation:
```bash
wget https://raw.githubusercontent.com/siyamsarker/WireShield/master/wireshield.sh -O wireshield.sh && chmod +x wireshield.sh && sudo ./wireshield.sh
```

After installation, you can run the script again to:
- Add new VPN clients
- List existing clients
- Revoke client access
- Uninstall WireShield completely
 
## Troubleshooting

If something doesn’t work as expected, try these quick checks.

- Port and connectivity
  - The installer picks a UDP port (random high port by default). Ensure it’s open on your provider’s firewall/security group and any OS firewall.
  - Optional: If you’re using UFW, allow your chosen UDP port:
    ```bash
    sudo ufw allow <your_port>/udp
    sudo ufw reload
    ```

- Service status and peers
  - Check WireGuard service:
    ```bash
    sudo systemctl status wg-quick@wg0
    ```
  - Show current peers and runtime info:
    ```bash
    sudo wg show
    ```

- Kernel and module support
  - WireGuard is built into Linux kernel 5.6+. On older kernels a module is installed.
  - Verify versions:
    ```bash
    uname -r
    wg --version
    ```
  - If you see “Cannot find device wg0” after install, reboot the server first. On older kernels you may need the module loaded:
    ```bash
    sudo modprobe wireguard  # if available on your distro
    ```

- Firewall specifics (iptables/firewalld)
  - The script sets iptables or firewalld rules automatically. If you use a different firewall (e.g. UFW), ensure the UDP port is allowed.
  - firewalld quick check:
    ```bash
    sudo firewall-cmd --list-ports
    ```

- No internet from the client
  - Try rebooting the server (after kernel/package updates).
  - Ensure IP forwarding is enabled (the installer writes /etc/sysctl.d/wg.conf):
    ```bash
    sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
    ```
  - DNS issues? Set client DNS during install or edit the client config’s DNS line.

- MTU problems (slow/unstable)
  - Some networks need a lower MTU. In the client config, try uncommenting and setting `MTU = 1420`.
  - See the linked MTU finder tool in the client config comments.

- Mobile/NAT environments
  - If the client sits behind NAT and drops after idle, enable PersistentKeepalive (e.g. `25`) in the client’s `[Peer]` section.

- QR code not shown
  - Make sure `qrencode` is installed (the installer attempts to install it where available).

## Providers

I recommend these cheap cloud providers for your VPN server:

- [Vultr](https://www.vultr.com/?ref=8948982-8H): Worldwide locations, IPv6 support, starting at \$5/month
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Germany, Finland and USA. IPv6, 20 TB of traffic, starting at 4.5€/month
- [Digital Ocean](https://m.do.co/c/ed0ba143fe53): Worldwide locations, IPv6 support, starting at \$4/month

## Contributing

## Discuss changes

Please open an issue before submitting a PR if you want to discuss a change, especially if it's a big one.

### Code formatting

This repository does not use CI or enforce lint/tests. If you want to check script quality locally, you can optionally use:
- [shellcheck](https://github.com/koalaman/shellcheck) for static analysis
- [shfmt](https://github.com/mvdan/sh) for formatting

## Credits & Licence

This project is under the [MIT Licence](https://raw.githubusercontent.com/siyamsarker/WireShield/master/LICENSE)

 
