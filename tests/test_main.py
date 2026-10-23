"""Exit codes of the entry point and Ctrl+C handling."""
import asyncio
import os
import signal
import sys
from types import SimpleNamespace

import pytest

from analysis import certificates_analysis, main
from db.database import DatabaseType


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


def test_cancelled_analysis_exits_with_code_130(monkeypatch):
    async def cancelled():
        raise asyncio.CancelledError

    monkeypatch.setattr(main, "certificates_analysis_main", cancelled)
    with pytest.raises(SystemExit) as exit_info:
        main.main()
    assert exit_info.value.code == 130


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
def test_ctrl_c_cancels_an_awaited_stage_and_restores_the_handler():
    async def stage():
        with certificates_analysis._ctrl_c_cancels_current_task():
            assert signal.getsignal(signal.SIGINT) is not signal.default_int_handler
            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.sleep(5)

    # As main(): asyncio.run() would install its own Ctrl+C handler. Ctrl+C may be ignored by the caller (background job)
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    loop = asyncio.new_event_loop()
    try:
        with pytest.raises(asyncio.CancelledError):
            loop.run_until_complete(stage())
        assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
    finally:
        loop.close()
        signal.signal(signal.SIGINT, previous)


def test_render_processes_are_kept_only_for_a_plot_stage_that_follows_at_once():
    def target(**stages):
        return SimpleNamespace(config=certificates_analysis.StageConfig(DatabaseType.LEAF, **stages))

    assert certificates_analysis._plots_at_once(target(plot=True))
    assert not certificates_analysis._plots_at_once(target(plot=True, ocsp=True))
    assert not certificates_analysis._plots_at_once(target(zlint=True))
    assert not certificates_analysis._plots_at_once(None)
