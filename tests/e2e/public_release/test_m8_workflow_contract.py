"""Static CI contract for the local M8 browser implementation gate."""

from pathlib import Path


def test_ci_runs_the_locked_retry_free_m8_browser_gate() -> None:
    root = Path(__file__).resolve().parents[3]
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    config = (root / "tests" / "e2e" / "public_release" / "playwright.config.ts").read_text(
        encoding="utf-8"
    )

    assert "working-directory: tests/e2e/public_release" in workflow
    assert "Install uv for the fixed API server" in workflow
    assert "uv sync --package stateweaver-api --locked" in workflow
    assert "run: npm ci" in workflow
    assert "run: npm run install:chromium" in workflow
    assert "run: npm run verify" in workflow
    assert "retries: 0" in config
    assert "reuseExistingServer: false" in config
    assert "PLAYWRIGHT_TEST_BASE_URL" in config
