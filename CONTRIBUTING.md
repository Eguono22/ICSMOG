# Contributing to ICSMOG

Thanks for contributing to ICSMOG.

## Getting Started

Clone the repository and install the project dependencies:

```bash
git clone https://github.com/Eguono22/ICSMOG.git
cd ICSMOG
pip install -r requirements.txt
pip install pytest ruff
```

If you prefer `uv` locally, the equivalent commands work as well, but the
project CI currently uses `pip`.

## Local Quality Checks

Before opening a pull request, run the same checks used in CI:

```bash
python -m ruff check .
python -m pytest -p no:cacheprovider tests -v
```

Optional `uv` equivalents:

```bash
uv run --with ruff ruff check .
uv run --with pytest pytest -p no:cacheprovider tests -v
```

## Development Notes

- Keep changes focused and small when possible.
- Add or update tests when behavior changes.
- Prefer updating documentation when CLI behavior, workflows, or setup steps change.
- Avoid committing local-only artifacts such as caches or generated lockfiles that are not part of the project workflow.

## Pull Requests

When preparing a pull request:

1. Make sure linting passes.
2. Make sure the test suite passes.
3. Summarize the user-facing or developer-facing change clearly.
4. Mention any follow-up work or known limitations.

## Release Checklist

Before cutting a release or merging a larger change set:

1. Run `python -m ruff check .`
2. Run `python -m pytest -p no:cacheprovider tests -v`
3. Confirm GitHub Actions checks are green.
4. Update `README.md` or `CONTRIBUTING.md` if setup, CLI behavior, or workflows changed.
