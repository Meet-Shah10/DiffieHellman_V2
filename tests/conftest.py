"""
tests/conftest.py — pytest configuration.

Marks slow tests (subprocess-based integration tests that spawn real OS processes
with expensive operations like RSA.generate(2048)) so they are skipped by default.

Run slow tests with:  pytest --run-slow
"""
import pytest


def pytest_addoption(parser):
    parser.addoption(
        '--run-slow', action='store_true', default=False,
        help='Run tests marked @pytest.mark.slow (subprocess integration tests)'
    )


def pytest_configure(config):
    config.addinivalue_line(
        'markers',
        'slow: marks tests as slow (subprocess integration; skip unless --run-slow)'
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption('--run-slow'):
        skip_slow = pytest.mark.skip(
            reason='Slow subprocess integration test. Run with: pytest --run-slow'
        )
        for item in items:
            if 'slow' in item.keywords:
                item.add_marker(skip_slow)
