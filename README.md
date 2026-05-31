# fortress-compliance-test

Automated compliance tests for testbank. PRs in this repo are opened by
Fortress Labs Pipeline 2 — each PR contains a generated pytest file
covering one CFR obligation. Review the citations + thresholds, add
fixtures in `tests/compliance/conftest.py` pointing at real bank systems,
and merge to unblock deploys.

Generated tests live in `tests/compliance/`. CI runs `pytest tests/compliance/`
on every PR.
