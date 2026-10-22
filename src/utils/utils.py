import argparse
import logging
import warnings

from rich.logging import RichHandler
from tqdm.rich import tqdm
from tqdm.std import TqdmExperimentalWarning

# Admin: Anuar Elio Magliari
# Politecnico di Torino

LOG_FILE = "app.log"
FILE_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s() - %(message)s"
BAR_FORMAT = "{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} • ⚡ {rate_fmt}"


class ArgparseFormatter(argparse.RawTextHelpFormatter):
    """Help formatter: raw text, wider option column and a left margin."""

    MARGIN = " "

    def __init__(self, *args, **kwargs):
        super().__init__(*args, max_help_position=40, **kwargs)

    def _format_action(self, action):
        return self.MARGIN + super()._format_action(action)

    def format_help(self):
        return self.MARGIN + super().format_help().replace("\n", "\n" + self.MARGIN)


def setup_logging(is_verbose: bool) -> None:
    """Configure logging to file (app.log) and console."""
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter(FILE_LOG_FORMAT))

    console_handler = RichHandler(rich_tracebacks=True)
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    logging.basicConfig(level=logging.DEBUG if is_verbose else logging.INFO, handlers=[file_handler, console_handler])


def progress_bar(total: int, description: str, colour: str, unit: str = "cert.", **kwargs) -> tqdm:
    """Create a progress bar (usable as a context manager) preceded by an empty line."""
    tqdm.write("")
    # tqdm.rich warns that it is experimental on every bar it creates
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", TqdmExperimentalWarning)
        return tqdm(total=total, desc=description, unit=unit, colour=colour, bar_format=BAR_FORMAT, **kwargs)
