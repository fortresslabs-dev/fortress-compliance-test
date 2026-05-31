"""Shared fixtures for Fortress-generated compliance tests.

Pipeline 2 generates one pytest file per CFR obligation under
tests/compliance/. Add bank-system fixtures here (DB connections, wire
client, OFAC client, etc.) so generated tests can request them by name
without hard-coding endpoints.
"""
import pytest


@pytest.fixture
def bank_system():
    """Placeholder. Replace with a real bank-system client/session."""
    raise NotImplementedError(
        "Add a real bank_system fixture in tests/compliance/conftest.py "
        "before merging compliance test PRs."
    )
