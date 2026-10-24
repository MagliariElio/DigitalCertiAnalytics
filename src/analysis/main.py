import asyncio
import logging
import sys

from analysis.certificates_analysis import INTERRUPT_MESSAGE, certificates_analysis_main

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Attempts to cancel the tasks still pending after an interrupt
CANCELLATION_ROUNDS = 3

# Standard exit code for Ctrl+C, so chained shell commands stop
SIGINT_EXIT_CODE = 130


def _cancel_pending_tasks(loop: asyncio.AbstractEventLoop) -> bool:
    """Cancel pending tasks; return True if another KeyboardInterrupt arrived meanwhile."""
    interrupted = False
    for _ in range(CANCELLATION_ROUNDS):
        pending = asyncio.all_tasks(loop)
        if not pending:
            break

        for task in pending:
            task.cancel()

        # A task that received the KeyboardInterrupt re-raises it while being cancelled: retry
        try:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except KeyboardInterrupt:
            interrupted = True
    return interrupted


def main() -> None:
    """Run the analysis in a new event loop, handling Ctrl+C."""
    # Since Python 3.14 asyncio.get_event_loop() no longer creates a loop implicitly
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    interrupted = False
    status = 0
    try:
        status = loop.run_until_complete(certificates_analysis_main()) or 0
    except KeyboardInterrupt:
        interrupted = True
        logging.info(INTERRUPT_MESSAGE)
    except asyncio.CancelledError:
        # Ctrl+C during an asynchronous stage: already logged when the task was cancelled
        interrupted = True
    finally:
        try:
            interrupted = _cancel_pending_tasks(loop) or interrupted
        finally:
            loop.close()

    if interrupted:
        sys.exit(SIGINT_EXIT_CODE)
    if status:
        sys.exit(status)


if __name__ == "__main__":
    main()
