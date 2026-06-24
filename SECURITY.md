# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in DORAKULA, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email the maintainer directly (see GitHub profile)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Release**: Within 30 days (severity-dependent)

## Security Features

DORAKULA implements the following security measures:

- API key authentication (constant-time comparison)
- Rate limiting (100 req/60s per client)
- Audit logging (SQLite, all auth events)
- HMAC signature verification (optional)
- Per-endpoint rate limiting
- Fail-closed authentication (no open mode)

## Authorized Use Only

DORAKULA is designed for authorized security testing only. Unauthorized use
against systems you do not own or have explicit permission to test is illegal.

