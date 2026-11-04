from app import read_doc


def test_hello():
    assert "hello docs" in read_doc("hello.txt")
