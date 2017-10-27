import pytest


def pytest_addoption(parser):
    parser.addoption("--integration", action="store_true", help="run integration tests")


def pytest_runtest_setup(item):
    if 'integration' in item.keywords:
        if not item.config.getoption("--integration"):
            pytest.skip("need --integration option to run")
