import logging
import hashlib
from urllib.parse import urlparse
from mitmproxy import http

def gen_hash(path, client_id, salt, body):
    return hashlib.sha256((path+client_id+body+salt).encode('utf-8')).hexdigest()

def request(flow: http.HTTPFlow) -> None:
    client_id = "0388941f"
    salt = "vinegar"

    url_parsed = urlparse(flow.request.url)
    path = url_parsed.path
    body = flow.request.content.decode("utf-8")

    logging.info ("URL: " + flow.request.url)
    logging.info ("Path: " + path)
    logging.info ("Client ID: " + client_id)
    logging.info ("Body: " + body)

    token = gen_hash (path, client_id, salt, body)
    logging.info ("Token: " + token)

    flow.request.headers["bearer"] = token
    flow.request.headers["client-id"] = client_id
