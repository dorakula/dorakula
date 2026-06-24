# Contributing to DORAKULA

Thank you for your interest in contributing to DORAKULA! This document
describes how to set up your development environment and submit changes.

## Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/dorakula/dorakula.git
cd dorakula

# 2. Create virtual environment
python3 -m venv dorakula-env
source dorakula-env/bin/activate

# 3. Install dependencies
pip install -r requirements.txt -r requirements.dev.txt

# 4. Start the server (needed for tests)
python dorakula_server.py --no-ai --port 9092

# 5. In another terminal, run tests
pytest tests/ -v -k "not rate_limit"
```

## Code Style

- Follow PEP 8 (use `flake8` or `ruff` to check)
- Use type hints for all public functions
- Add docstrings for all classes and public methods
- Keep functions under 50 lines where possible
- No new dependencies without justification (ponytail principle)

## Testing

- All new features must include tests in `tests/`
- Run `pytest tests/ -v --cov` to check coverage
- Target: 70%+ coverage on new code
- Tests that consume rate limit quota should be marked `@pytest.mark.rate_limit`

## Submitting Changes

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes following the code style above
3. Run tests: `pytest tests/ -v -k "not rate_limit"`
4. Commit with conventional commit format:
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation only
   - `chore:` maintenance
   - `test:` test additions
5. Push and create a Pull Request to `main`

## Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

Example:
```
feat(security): add HMAC signature verification

Optional HMAC-SHA256 signature verification for request integrity.
Clients can send X-Dorakula-Signature header. If absent, falls back
to API key only (backward compatible).

Closes #42
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full architecture overview.

## Security

- **Never commit API keys, tokens, or secrets**
- **Never commit `.env` files** (they're in `.gitignore`)
- Report security vulnerabilities privately to the maintainers
- All security-related changes should be reviewed carefully

## Questions?

Open an issue with the `question` label.
