"""Exit codes of the entry point."""
import asyncio

import pytest

from analysis import main


@pytest.fixture(autouse=True)
def reset_event_loop():
    yield
    asyncio.set_event_loop(None)


def test_interrupt_exits_with_code_130(monkeypatch):
    async def interrupted():
        raise KeyboardInterrupt

    monkeypatch.setattr(main, "certificates_analysis_main", interrupted)
    with pytest.raises(SystemExit) as exit_info:
        main.main()
    assert exit_info.value.code == 130


def test_normal_run_exits_normally(monkeypatch):
    async def completed():
        return None

    monkeypatch.setattr(main, "certificates_analysis_main", completed)
    assert main.main() is None
