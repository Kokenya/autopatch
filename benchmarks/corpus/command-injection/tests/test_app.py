from app import ping


def test_localhost():
    assert ping("127.0.0.1") == 0
