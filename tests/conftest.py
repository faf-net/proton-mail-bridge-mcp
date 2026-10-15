"""Test-Grundeinstellungen: der Server baut sich beim Import auf und braucht
mindestens ein statisches Token — hier ein Wegwerf-Token nur für die Tests."""

import os

os.environ.setdefault("MCP_STATIC_TOKENS", "test=" + "t" * 32 + ":proton.read,proton.attachments")
os.environ.setdefault("MCP_OAUTH_ENABLED", "false")
os.environ.pop("MCP_AUTH_TOKEN", None)
