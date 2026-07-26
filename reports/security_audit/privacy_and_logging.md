# Privacy and logging

Raw email, HTML, full headers, addresses, subjects, URLs, attachment names, Firebase credentials, and environment values are not intentionally logged. Parser and Firebase failure logs use generic messages. API responses use safe reason codes/messages and do not expose absolute paths or exception names. Browser reports exclude raw bodies and full raw headers; local storage behavior and retention semantics were not redesigned.

Residual concern: deployment logging configuration must keep framework/debug logging disabled and protect access to logs.
