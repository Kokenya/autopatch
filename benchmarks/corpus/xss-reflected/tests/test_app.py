from app import render


def test_plain():
    assert render("bob") == "<h1>Hello bob</h1>"
