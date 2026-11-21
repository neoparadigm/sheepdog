.PHONY: setup lint type test fuzz bench verify
PY = uv run python
setup:
	uv sync --extra dev --frozen
lint:
	uv run ruff check src tests agents bench
	uv run ruff format --check src tests agents bench
type:
	uv run mypy --strict
test:
	uv run pytest tests/unit tests/property --cov --cov-report=term-missing:skip-covered
fuzz:
	uv run pytest tests/fuzz --hypothesis-seed=0
bench:
	$(PY) -m bench.injection_gauntlet.run --out bench/report.md
verify: lint type
	$(PY) tools/check_suites.py
	$(PY) tools/check_hygiene.py
	uv run pytest tests --ignore=tests/perf --cov --cov-report=term-missing:skip-covered
	uv run pytest tests/perf
