import asyncio
import logging
import threading

from utils import log_replay


class ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(f"{record.levelname} {record.getMessage()}")


def test_problems_are_handled_once_per_occurrence_and_handlers_are_restored():
    handler = ListHandler()
    root = logging.getLogger()
    root.addHandler(handler)
    previous_level = root.level
    root.setLevel(logging.DEBUG)
    try:
        with log_replay.replaying():
            with log_replay.replaying():      # nested blocks keep the outer wrapper
                with log_replay.repeated(3):
                    logging.info("progress")
                    logging.warning("problem")
                    logging.error("failure")
                logging.error("once")
            with log_replay.repeated(0):
                logging.error("at least once")
        with log_replay.repeated(2):
            logging.error("not wrapped")
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    assert handler.messages == ["INFO progress"] + ["WARNING problem"] * 3 + ["ERROR failure"] * 3 + [
        "ERROR once", "ERROR at least once", "ERROR not wrapped"]
    assert "handle" not in handler.__dict__


def test_count_is_per_thread_and_per_task():
    handler = ListHandler()
    logging.getLogger().addHandler(handler)
    try:
        with log_replay.replaying():
            def work(name, count):
                with log_replay.repeated(count):
                    logging.error(name)

            threads = [threading.Thread(target=work, args=(f"thread{i}", i + 1)) for i in range(3)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            async def task(name, count):
                with log_replay.repeated(count):
                    await asyncio.sleep(0.01)
                    logging.error(name)

            async def tasks():
                with log_replay.repeated(5):
                    # A task started inside the block copies the count, and can reset it for its own records
                    inherited = asyncio.ensure_future(task("inherited", 1))
                    await asyncio.gather(task("a", 2), task("b", 1), inherited)
                    logging.error("outer")

            asyncio.run(tasks())
    finally:
        logging.getLogger().removeHandler(handler)

    assert sorted(handler.messages) == sorted(
        ["ERROR thread0"] + ["ERROR thread1"] * 2 + ["ERROR thread2"] * 3 + ["ERROR a"] * 2 + ["ERROR b"]
        + ["ERROR inherited"] + ["ERROR outer"] * 5)
