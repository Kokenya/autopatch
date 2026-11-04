from app import safe_next


def test_local():
    assert safe_next("/home") == "/home"
