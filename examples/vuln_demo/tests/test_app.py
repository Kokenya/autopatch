from app import find_user, read_doc


def test_find_existing_user():
    assert find_user("alice") == ("alice", "admin")


def test_missing_user():
    assert find_user("mallory") is None


def test_read_doc():
    assert "hello from the docs folder" in read_doc("hello.txt")
