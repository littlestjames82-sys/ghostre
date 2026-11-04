# Contributing to ghostre

ghostre is a Ghost Developer Studio project. Contributions are welcome. The bar is receipts: if a change claims a capability, the test suite or a documented check proves it.

## Dev setup

```bash
git clone https://github.com/littlestjames82-sys/ghostre
cd ghostre
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Verify before you send

Run the test suite in `tests/` before opening a pull request, and add tests for new behavior. If the README documents a different test command for this project, that command wins.

## Rules

- Keep changes focused. One pull request, one purpose.
- No new runtime dependencies without discussion first. Most Ghost tools are standard library only by design, and that is a feature, not a gap.
- No secrets in code, tests, or examples. Keys and credentials come from the environment only, and are never committed or logged.
- Honest status. Unproven things are called unproven, in the README, in test output, and in your pull request description.
- Match the existing style of the file you are editing.

## Pull requests

- Describe what changed, why, and how you verified it.
- Note anything you did not test.
- Releases are maintainer-run. A merged pull request is not a release.

By Ghost Developer Studio: https://github.com/littlestjames82-sys
