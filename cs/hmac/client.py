""" Crowdstrike Rest Client """

import sys
import hmac
import hashlib
import base64
import email
import json
import requests
try:
    import urlparse
except:
    import urllib.parse
try:
    import urllib
except:
    import urllib.request, urllib.parse, urllib.error
import collections
import functools
import os
import posixpath

def enable_debug():
    """ Enable debug mode """
    import logging
    try:
        import httplib as http_client
    except:
        import http.client as http_client

    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig() 
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

Auth = collections.namedtuple('Auth', ['uuid', 'api_key', 'access'])

def add_auth(func):
    """ Decorator to add auth """
    def wrapped(*args, **kwargs):
        """ Pull out auth or create it """
        if 'headers' in kwargs:
            try:
                data = map(str.lower, kwargs.get('headers').keys())
            except:
                data = list(map(str.lower, list(kwargs.get('headers').keys())))
            if 'authorization' in data:
                return func(auth=None, *args, **kwargs)
        auth = kwargs.pop('Auth', None)
        if not auth:
            uuid = kwargs.pop('uuid', None)
            api_key = kwargs.pop('api_key', None)
            access = kwargs.pop('access', None)
            if not all([uuid, api_key, access]):
                raise Exception("uuid, api_key and access are all required")
            auth = Auth(uuid, api_key, access)
        return func(auth=auth, *args, **kwargs)
    return wrapped

@add_auth
def do_request(url, method, auth, **req_args):
    """ Make the actual request """

    headers = requests.structures.CaseInsensitiveDict(req_args.pop('headers', {}))
    if not auth:
        return getattr(requests, method.lower())(url, headers=headers, **req_args)

    if "Date" not in headers:
        headers['Date'] = email.utils.formatdate(localtime=False, usegmt=True)

    params_string = None
    if "params" in req_args:
        try:
            params_string = urllib.urlencode(req_args.get('params'), True)
        except:
            params_string = urllib.parse.urlencode(req_args.get('params'), True)

    content_md5 = md5(**req_args)

    headers['Authorization'] = sign_request(
            url,
            method,
            content_md5,
            params_string,
            headers,
            auth
    )

    return getattr(requests, method.lower())(url, headers=headers, **req_args)


def md5(**args):
    """ Create an MD5 of the body contents using either the body or json arguments """
    def _hash(body):
        """ Generate the body hash """
        return base64.b64encode(hashlib.md5(body).digest())
    if "json" in args:
        return _hash(json.dumps(args["json"]))
    elif "data" in args:
        return _hash(args["data"])
    else:
        return ""


def sign_request(url, method, content_md5, params_string, headers, auth):
    """ Create the appropriate Authorization header by signing the relevent data """
    date = headers.get('x-cs-date', headers['Date'])
    (path, query) = normalize_uri(url, params_string)
    signature = api_signature(method, content_md5, date, path, query, auth)
    if auth.access == "users":
        return "cs-hmac {}:{}".format(auth.uuid, signature)
    else:
        return "cs-hmac {}:{}:{}".format(auth.uuid, signature, auth.access)


def canonicalize_path(uri, charset='utf-8'):
    """ Create a canonical representation of the path """
    try:
        data = isinstance(uri, unicode)
    except:
        data = isinstance(uri, str)
    if data:
        uri = uri.encode(charset, 'ignore')
        if type(uri) != str:
            uri = uri.decode()
    try:
        scheme, netloc, path, qs, anchor = urlparse.urlsplit(uri)
        path = urllib.quote(path, '/%')
    except:
        scheme, netloc, path, qs, anchor = urllib.parse.urlsplit(uri)
        path = urllib.parse.quote(path, '/%')
    return '{}{}'.format(netloc, posixpath.normpath(path))


def canonicalize_query(query, params_string):
    """ Create a canonical representation of the query string.  If we have a
    query string attached to the url, and params argument, deal with that here """
    try:
        q = "&".join(filter(None, [query, params_string]))
    except:
        q = "&".join([_f for _f in [query, params_string] if _f])
    try:
        parsed = urlparse.parse_qs(q, keep_blank_values=True).items()
    except:
        parsed = list(urllib.parse.parse_qs(q, keep_blank_values=True).items())
    try:
        canon_args = sorted({k: map(urllib.quote, v) for k, v in parsed}.items())
    except:
        canon_args = sorted({k: list(map(urllib.parse.quote, v)) for k, v in parsed}.items())
    try:
        return urllib.urlencode([(i[0], [urllib.unquote(p) for p in i[1]]) for i in canon_args], True)
    except:
        return urllib.parse.urlencode([(i[0], [urllib.parse.unquote(p) for p in i[1]]) for i in canon_args], True)


def normalize_uri(url, params_string):
    """ Created a normalized uri by combining the canonical path and canonical qs """
    canonical_path = canonicalize_path(url)
    try:
        uri = urlparse.urlparse(url)
    except:
        uri = urllib.parse.urlparse(url)
    canonical_query = canonicalize_query(uri.query, params_string)
    return (canonical_path, canonical_query)


def api_signature(method, content_md5, date, path, query_string, auth):
    """ Do the signing of the content """
    string_to_sign = "\n".join([method, content_md5, date, path, query_string])
    if sys.version_info[0] == 2:
        dig = hmac.new(auth.api_key, string_to_sign, hashlib.sha256).digest()
    else:
        dig = hmac.new(auth.api_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(dig).decode() 


## PUBLIC API ##

get = functools.partial(do_request, method="GET")

post = functools.partial(do_request, method="POST")

put = functools.partial(do_request, method="PUT")

delete = functools.partial(do_request, method="DELETE")

patch = functools.partial(do_request, method="PATCH")

head = functools.partial(do_request, method="HEAD")

