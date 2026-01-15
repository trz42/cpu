# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU - The next-generation EESSI build-and-deploy bot.

Function tracing decorator for debugging.
"""

from __future__ import annotations

import logging
from functools import wraps
from typing import Any, Callable, TypeVar

from cpu.logging import TRACE

F = TypeVar('F', bound=Callable[..., Any])


def trace_calls(
    level: int = TRACE,
    include_args: bool = True,
    include_result: bool = True,
) -> Callable[[F], F]:
    """
    Decorator to trace function entry/exit.

    Args:
        level: Logging level for trace messages
        include_args: Whether to log function arguments
        include_result: Whether to log return value

    Returns:
        Decorated function

    Example:
        @trace_calls(level=logging.DEBUG)
        def my_function(x: int) -> int:
            return x * 2
    """

    def decorator(func: F) -> F:
        logger = logging.getLogger(func.__module__)

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # log entry
            if include_args:
                logger.log(level, f">>> {func.__name__}(args={args}, kwargs={kwargs})")
            else:
                logger.log(level, f">>> {func.__name__}()")

            try:
                result = func(*args, **kwargs)

                # log exit
                if include_result:
                    logger.log(level, f"<<< {func.__name__} = {result}")
                else:
                    logger.log(level, f"<<< {func.__name__}")

                return result

            except Exception as err:
                logger.log(level, f"X {func.__name__} raised {type(err).__name__}: {err}")
                raise

        return wrapper  # type: ignore[return-value]

    return decorator
