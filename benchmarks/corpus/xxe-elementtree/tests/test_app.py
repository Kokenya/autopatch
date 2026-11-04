from app import parse_feed


def test_plain():
    assert parse_feed("<r>ok</r>").text == "ok"
