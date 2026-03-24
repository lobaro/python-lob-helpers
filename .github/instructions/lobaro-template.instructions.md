---
applyTo: "**"
---
# Lobaro Project Instructions

## Project layout

- Source: `src/lob_hlpr/` — all library/app code lives here
- Tests: `tests/`
- Config: `pyproject.toml`, if configs can be in different files, prefer that (e.g. `tox.ini`, `pytest.ini`)
- Versioning: `setuptools-scm` — version comes from git tags, never hardcode it
- Dependencies: loose version bounds in `pyproject.toml`; pinned snapshots in `requirements*.txt`

## Python version

Python ≥ 3.10. Always use built-in generics — `list[X]`, `dict[K, V]`, `X | None` — never `typing.List` etc.

## Validation workflow

Always run lint first, fix all issues, then run the full test suite:

```
tox -e lint   # check and fix all style issues
tox           # full test suite across Python versions
```

If lint passes but tests fail, diagnose the test failure — do not bypass checks.

## Code patterns

- Use `dataclasses.dataclass` for data containers — never Pydantic (not a dependency)
- Use `logging` in every module — never `print` in library code
- Prefer named functions over lambdas
- Follow PEP 8 and PEP 257
- Type-hint all public functions and methods
- Try not to add third-party dependencies unless necessary — prefer built-in features

## Agents

- PR review agent: [instructions](../agents/pr-review.agent.md)
