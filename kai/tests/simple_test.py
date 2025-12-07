import pytest

@pytest.fixture
def simple_fixture():
    return 42


def test_simple_test(simple_fixture):
    assert simple_fixture == 42