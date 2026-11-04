from app import find_user


def test_alice():
    assert find_user("alice") == ("alice", "admin")
