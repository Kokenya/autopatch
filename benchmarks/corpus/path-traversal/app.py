import os

DOCS = os.path.join(os.path.dirname(__file__), "docs")


def read_doc(name):
    with open(os.path.join(DOCS, name)) as f:
        return f.read()
