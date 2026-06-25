# CI Workflow Temporarily Disabled

GitHub Actions failed with:
```
The job was not started because your account is locked due to a billing issue.
```

## To Re-enable CI

1. Resolve billing at https://github.com/settings/billing
2. Check spending limit at https://github.com/settings/billing/spending_limit
3. Once billing is resolved:
   ```bash
   git mv .github/workflows/ci.yml.disabled .github/workflows/ci.yml
   git commit -m "ci: re-enable workflow (billing resolved)"
   git push origin main
   ```

## Why This Happened

Even though dorakula/dorakula is a PUBLIC repo (Actions should be free unlimited),
GitHub locks ALL Actions across the account when there is an unpaid bill or
exceeded spending limit anywhere in the account.

## Alternative

If you do not want to pay for GitHub Actions:
- Keep CI disabled (this file stays)
- Run tests manually: `pytest tests/ -v --tb=short -k "not rate_limit"`
- Or migrate to GitLab CI / CircleCI (free tiers available)

## Note on YAML

The ci.yml YAML syntax was already correct (`branches: [main]`).
Terminal display showing `ain]` is an ANSI escape rendering artifact
(the `[m` sequence resets terminal color), NOT a real syntax error.
