from urllib.parse import urlsplit


def safe_next(next_url):
    if (not next_url or urlsplit(next_url).netloc != ''
            or not next_url.startswith('/') or next_url[1:2] in ('/', chr(92))
            or any(ord(c) < 32 or ord(c) == 127 or c == chr(92) for c in next_url)):
        return '/'
    return next_url
