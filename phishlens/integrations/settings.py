"""
Reads secrets (API keys) from the environment or Streamlit secrets.

Keys are never hard-coded, never logged and never shown in the UI.
For local development put them in a `.env`-style shell export or in
`.streamlit/secrets.toml` (both are git-ignored). In Azure, the same
environment variables can be filled from Azure Key Vault references,
so no code change is needed later.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def get_secret(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    if value:
        return value
    try:
        import streamlit as st

        secret = st.secrets.get(name)  # type: ignore[no-untyped-call]
    except Exception as exc:  # no secrets.toml, or not running under Streamlit
        logger.debug("Streamlit secrets unavailable for %s (%s)", name, type(exc).__name__)
        return None
    return str(secret).strip() if secret else None
