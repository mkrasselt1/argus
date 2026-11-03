"""Fixtures for the Home Assistant integration tests.

Run with:  pip install pytest-homeassistant-custom-component
           pytest tests_homeassistant
"""
import pytest

pytest_plugins = ["pytest_homeassistant_custom_component"]


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield
