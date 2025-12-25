# WireShield Tests

This directory contains test scripts for WireShield.

## Test Scripts

### Deployment Tests (Bash)

**tests/test-2fa-access.sh**
- Tests 2FA service accessibility from different interfaces
- Verifies HTTPS endpoints work on loopback, VPN IP, and public IP
- Checks iptables DNAT rules for hairpin NAT
- **Run on server after installation**

**tests/test-integration.sh**
- Validates 2FA service installation
- Checks Python dependencies
- Verifies systemd service configuration
- Tests database initialization
- **Run on server after installation**

### Unit Tests (Python)

**2fa-auth/tests/test_rate_limit.py**
- Unit tests for rate limiting functionality
- Tests request throttling behavior
- Requires pytest
- **Run during development**: `cd 2fa-auth && pytest tests/test_rate_limit.py`

## Running Tests

### On Server (Post-Installation)
```bash
cd ~/WireShield
sudo bash tests/test-2fa-access.sh
sudo bash tests/test-integration.sh
```

### Local Development
```bash
cd 2fa-auth
pytest tests/test_rate_limit.py
```

## Are All Tests Needed?

**YES** - Each test serves a different purpose:

1. **test-2fa-access.sh** - Essential for verifying network connectivity and NAT rules work correctly
2. **test-integration.sh** - Essential for validating proper installation and dependencies  
3. **test_rate_limit.py** - Essential for ensuring rate limiting prevents abuse

All three tests are recommended for a production deployment.
