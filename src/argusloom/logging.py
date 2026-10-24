"""Structured logging configuration for the ArgusLoom service."""

from __future__ import annotations

import logging

import structlog


def setup_logging(level: str = "INFO") -> None:
    """Configure structlog to emit JSON logs using the requested verbosity."""

    log_level = getattr(logging, level.upper(), logging.INFO)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(level=log_level, format="%(message)s")


def get_logger(name: str) -> structlog.BoundLogger:
    """Return a logger bound to the given component name."""

    return structlog.get_logger(name)
