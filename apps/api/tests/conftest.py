"""Pytest configuration and fixtures."""

from __future__ import annotations

import os
import sys

# Add the app directory to path so imports work correctly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
