"""
Logging utility for CloudAuditor.
"""

import logging
import sys
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console

console = Console()


def get_logger(name: str, verbose: bool = False) -> logging.Logger:
    """
    Get a configured logger instance with Rich formatting.

    Args:
        name: Name of the logger (typically __name__)
        verbose: If True, set log level to DEBUG; otherwise INFO

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger

    # Set log level based on verbose flag
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)

    # Create Rich handler for beautiful console output
    handler = RichHandler(
        console=console,
        show_time=True,
        show_path=verbose,
        markup=True,
        rich_tracebacks=True,
    )
    handler.setLevel(log_level)

    # Create formatter
    formatter = logging.Formatter(
        "%(message)s",
        datefmt="[%X]",
    )
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)

    return logger


def setup_logging(verbose: bool = False) -> None:
    """
    Configure root logger for the application.

    Args:
        verbose: Enable debug logging if True
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                show_time=True,
                show_path=verbose,
                markup=True,
                rich_tracebacks=True,
            )
        ],
    )
