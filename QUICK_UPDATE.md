# 🚀 Quick Production Deployment - WireShield Dashboard

## ✨ What's Fixed in This Update

### Dashboard Issues Resolved:
✅ **Dashboard home now has proper widgets** - Stats cards showing Total/Active/Expiring clients and Server Status  
✅ **Fixed "Uninstall initiated" error** - Better script path detection with multiple fallback locations  
✅ **Fixed menu navigation** - All menus (Dashboard, Clients, Add Client, Status, Settings) now work correctly  
✅ **Fixed script not found error** - Enhanced path detection: `/root/wireshield.sh`, `/usr/local/bin/wireshield.sh`, etc.  
✅ **Logo consistency** - Login page (72px) and dashboard sidebar (42px) logos are properly sized  
✅ **Compact login form** - Made the login form more compact and smart-looking  

### New Features:
🎉 **Dashboard Home Page** - Beautiful stats overview with quick actions  
🎉 **Server Status Indicator** - Shows WireGuard Online/Offline status  
🎉 **Recent Clients Table** - Quick view of last 5 clients on home page  
🎉 **Quick Actions Panel** - One-click access to Add Client, View Clients, Status, Restart Service  

---

## 🎯 One-Command Update (Recommended)

Run this on your production server:

```bash
sudo su -
wget -O update-dashboard.sh https://raw.githubusercontent.com/siyamsarker/WireShield/master/update-dashboard.sh
chmod +x update-dashboard.sh
./update-dashboard.sh
```

**That's it!** The script will:
- Stop dashboard service
- Backup your config
- Update code from GitHub
- Rebuild the binary
- Fix script paths
- Update systemd service
- Restart dashboard
- Verify everything works

---

## 📋 Manual Update (Alternative Method)

If you prefer manual control:

```bash
# 1. Stop dashboard
sudo systemctl stop wireshield-dashboard

# 2. Backup config
sudo cp /etc/wireshield/dashboard-config.json /root/dashboard-config.backup

# 3. Update code
cd /opt/WireShield  # or wherever your repo is
git pull origin master

# 4. Rebuild binary
go build -o /usr/local/bin/wireshield-dashboard ./cmd/wireshield-dashboard

# 5. Ensure script is at /root
sudo cp wireshield.sh /root/wireshield.sh
sudo chmod +x /root/wireshield.sh

# 6. Update systemd service (add this line if missing)
sudo systemctl edit wireshield-dashboard
# Add under [Service]:
# Environment="WIRE_SHIELD_SCRIPT=/root/wireshield.sh"

# 7. Restart
sudo systemctl daemon-reload
sudo systemctl start wireshield-dashboard
```

---

## ✅ Verification Checklist

After update, verify everything works:

```bash
# 1. Check service is running
sudo systemctl status wireshield-dashboard
# Should show: "active (running)"

# 2. Check script exists
ls -la /root/wireshield.sh
# Should show: -rwxr-xr-x 1 root root ...

# 3. Check environment variable
sudo systemctl show wireshield-dashboard | grep WIRE_SHIELD_SCRIPT
# Should show: Environment=WIRE_SHIELD_SCRIPT=/root/wireshield.sh

# 4. Check logs for errors
sudo journalctl -u wireshield-dashboard -n 50 --no-pager
# Should not show any "No such file or directory" errors

# 5. Access dashboard in browser
# Navigate to http://YOUR_SERVER:51821
# Should see the new dashboard with stats cards
```

---

## 🎨 New Dashboard Preview

After update, you'll see:

### Home Page (Dashboard):
```
╔════════════════════════════════════════════════════╗
║  Dashboard                                         ║
║  Overview of your WireGuard VPN server            ║
╠════════════════════════════════════════════════════╣
║  [Total Clients: 5]  [Active: 3]                  ║
║  [Expiring: 2]       [Status: 🟢 Online]          ║
╠════════════════════════════════════════════════════╣
║  Quick Actions:                                    ║
║  [➕ Add New Client]  [👥 View All Clients]       ║
║  [📊 Server Status]   [🔄 Restart Service]        ║
╠════════════════════════════════════════════════════╣
║  Recent Clients:                                   ║
║  Client1  | Expires in 30 days | [⬇️] [QR]        ║
║  Client2  | No expiration      | [⬇️] [QR]        ║
╚════════════════════════════════════════════════════╝
```

---

## 🔧 Troubleshooting

### Dashboard still broken after update?

```bash
# View detailed logs
sudo journalctl -u wireshield-dashboard -f

# Common issues:
# 1. Script not found - Check: ls -la /root/wireshield.sh
# 2. Permission denied - Run: chmod +x /root/wireshield.sh
# 3. Binary outdated - Rerun: go build -o /usr/local/bin/wireshield-dashboard ./cmd/wireshield-dashboard
```

### Need to reinstall completely?

```bash
# Use the main installer
wget https://raw.githubusercontent.com/siyamsarker/WireShield/master/wireshield.sh
chmod +x wireshield.sh
sudo ./wireshield.sh
# Choose: "Web Dashboard (Install/Setup)"
```

---

## 📞 Support

- **Full Guide:** See `PRODUCTION_DEPLOY.md` in the repository
- **Issues:** Check logs with `sudo journalctl -u wireshield-dashboard -n 100 --no-pager`
- **GitHub:** https://github.com/siyamsarker/WireShield

---

## 🔑 Important Notes

1. **Backup First:** The update script backs up your config automatically
2. **Admin Password:** Your admin credentials remain unchanged
3. **Existing Clients:** All client configs are preserved
4. **No Downtime:** Only brief service restart (~2 seconds)
5. **Rollback:** If issues occur, restore from `/root/dashboard-config.backup`

---

**Made with ❤️ for production stability**

*Last updated: 2024 - Production-ready v2.0*
