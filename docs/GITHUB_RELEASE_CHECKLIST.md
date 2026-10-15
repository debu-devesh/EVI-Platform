# GitHub Release Checklist

Run this checklist before pushing to GitHub.

## 1) Repository Hygiene

- Remove temporary/local artifacts (logs, caches, generated exports).
- Confirm `.gitignore` excludes local data (`*.db`, uploads, extracted data, large media).
- Ensure no accidental root files remain (scratch files, local command dumps, empty exports).

## 2) Security and Privacy

- Verify no credentials or secrets are tracked (`.env`, keys, tokens).
- Verify no sensitive case/evidence files are tracked.
- Ensure local forensic datasets are excluded or anonymized.

## 3) Code and Tests

- Run tests from `FORENSIC/`:
  - `python -m pytest tests`
- Resolve any failing tests before push.
- Optionally run targeted smoke checks for upload/query flows.

## 4) Documentation Accuracy

- `README.md` has correct clone URL and startup commands.
- `SETUP_GUIDE.md` and `INSTALLATION.md` are consistent.
- Architecture docs in `FORENSIC/docs/` match current modules.
- Update `CHANGELOG.md` if release-worthy changes were made.

## 5) Final Git Checks

- Review staged changes with `git diff --staged`.
- Confirm no large binaries are staged unintentionally.
- Confirm commit message clearly describes why changes were made.

## 6) Push

- Push branch and open a PR if working in team workflow.
- Add summary, test plan, and risk notes in PR description.
