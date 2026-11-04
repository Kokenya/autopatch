def safe_next(next_url):
    if next_url is None or not next_url.startswith('/'):
        return '/'
    return next_url
