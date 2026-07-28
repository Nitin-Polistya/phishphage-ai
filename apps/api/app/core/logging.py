from __future__ import annotations

import contextvars
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any


request_id_context: contextvars.ContextVar[str | None] = contextvars.ContextVar('request_id', default=None)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        request_id = request_id_context.get()
        if request_id:
            payload['request_id'] = request_id
        structured = getattr(record, 'structured', None)
        if isinstance(structured, dict):
            payload.update({key: value for key, value in structured.items() if value is not None})
        if record.exc_info and getattr(record, 'include_traceback', False):
            payload['traceback'] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(',', ':'), sort_keys=True)


def log_event(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    fields.setdefault('event', message)
    logger.log(level, message, extra={'structured': fields})


def privacy_safe_client_ip(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()[:16]


def configure_logging(level: str = 'INFO', uvicorn_access_log: bool | None = None) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format='%(message)s',
        handlers=[logging.StreamHandler()],
        force=True,
    )
    for handler in logging.getLogger().handlers:
        handler.setFormatter(JsonFormatter())
    if uvicorn_access_log is not None:
        logging.getLogger('uvicorn.access').disabled = not uvicorn_access_log
