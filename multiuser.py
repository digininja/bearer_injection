import logging
import hashlib
from urllib.parse import urlparse
from mitmproxy import http

# The users

users = {
    "1": {
        "client_id": "0388941f",
        "salt": "vinegar"
        },
    "2": {
        "client_id": "4be75c87",
        "salt": "tabasco"
        },
    "3": {
        "client_id": "12345678",
        "salt": "hendos"
        }
}

def gen_hash(path, client_id, salt, body):
    return hashlib.sha256((path+client_id+body+salt).encode('utf-8')).hexdigest()

def request(flow: http.HTTPFlow) -> None:
    if 'user-id' in flow.request.headers:
        user_id = flow.request.headers['user-id']
        logging.info ("User-id: " + user_id)

        # The user ID -1 means do not add a header so just bail out now
        if user_id == "-1":
            return

        # See if we know about the requested user, if so, use it, if not, default to user 1
        if user_id in users:
            logging.info ("Using user " + user_id)
            user = users[user_id]
        else:
            logging.info ("Unknown user requested, using user 1")
            user = users["1"]
    else:
        logging.info ("No user supplied, using user 1")
        user = users["1"]

    url_parsed = urlparse(flow.request.url)
    path = url_parsed.path
    logging.info ("URL: " + flow.request.url)
    logging.info ("Path: " + path)
    logging.info ("Client ID: " + user["client_id"])
    logging.info ("Salt: " + user["salt"])

    # GET requests have an empty body so don't need to check
    # if GET or other method
    body = flow.request.content.decode("utf-8")
    logging.info ("Body: " + body)

    token = gen_hash (path, user["client_id"], user["salt"], body)
    logging.info ("Token: " + token)

    if "bearer" in flow.request.headers:
        logging.info ("Bearer token already passed, not modifying it")
    else:
        flow.request.headers["bearer"] = token

    if "client-id" in flow.request.headers:
        logging.info ("Client ID already passed, not modifying it")
    else:
        flow.request.headers["client-id"] = user['client_id']
