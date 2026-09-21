"""Capture actual HTTP/1.1 application exchanges without implicit redirects."""
from __future__ import annotations
import http.client
import json
import ssl
from urllib.parse import urlsplit

MAX_MESSAGE = 8 * 1024 * 1024


def ensure_content_length(headers, body):
    """Construct a request length; never use this on observed responses."""
    return [[k, v] for k, v in headers if k.lower() != 'content-length'] + [['Content-Length', str(len(body.encode('utf-8')))]]


def exchange(*, boundary, method, url, headers=None, body='', timeout=180.0):
    parts = urlsplit(url)
    if parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError('unsupported observation URL')
    payload = body.encode('utf-8')
    if len(payload) > MAX_MESSAGE:
        raise ValueError('request capture limit exceeded')
    sent = []
    base_class = http.client.HTTPSConnection if parts.scheme == 'https' else http.client.HTTPConnection
    class ObservedConnection(base_class):
        def send(self, data):
            if not isinstance(data, (bytes, bytearray, memoryview)):
                raise ValueError('streaming request outside selected capture contract')
            sent.append(bytes(data))
            super().send(data)
    connection = ObservedConnection(parts.hostname, parts.port, timeout=timeout)
    request_target = (parts.path or '/') + ('?' + parts.query if parts.query else '')
    header_list = list(headers or [])
    if not any(k.lower() == 'content-length' for k,v in header_list):
        header_list.append(['Content-Length', str(len(payload))])
    try:
        # putheader preserves caller duplicates; send() records automatic Host and Accept-Encoding too.
        connection.putrequest(method, request_target)
        for key, value in header_list:
            connection.putheader(key, value)
        connection.endheaders(payload)
        response = connection.getresponse()
        raw = response.read(MAX_MESSAGE + 1)
        if len(raw) > MAX_MESSAGE:
            raise ValueError('response capture limit exceeded')
        observed_headers = [list(pair) for pair in response.getheaders()]
        wire = b''.join(sent)
        head, separator, request_body = wire.partition(b'\r\n\r\n')
        if not separator:
            raise ValueError('incomplete request capture')
        lines = head.decode('iso-8859-1').split('\r\n')
        actual_headers = []
        for line in lines[1:]:
            key, colon, value = line.partition(':')
            if not colon:
                raise ValueError('malformed captured header')
            actual_headers.append([key, value.strip()])
        return {
            'boundary': boundary,
            'request': {'method': method, 'url': url, 'headers': actual_headers, 'body': request_body.decode('utf-8')},
            'response': {'status': response.status, 'headers': observed_headers, 'body': raw.decode('utf-8')},
        }
    finally:
        connection.close()


def decode_json(body):
    return json.loads(body)
