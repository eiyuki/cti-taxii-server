#!/usr/bin/env python
import json
import logging

from flask import g, has_request_context, request


class RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.method = request.method
            record.path = request.full_path.rstrip('?')
            record.server_protocol = request.environ.get('SERVER_PROTOCOL')

            source = request.headers.getlist('X-Forwarded-For')
            if request.remote_addr not in source:
                source.append(request.remote_addr)

            record.source = ",".join(source)
            record.user = getattr(g, 'user', '-')
            record.trace_id = getattr(g, 'trace_id', '-')
        else:
            record.method = '-'
            record.path = '-'
            record.server_protocol = '-'
            record.source = '-'
            record.user = '-'
            record.trace_id = '-'

        return super(RequestFormatter, self).format(record)


def default_request_formatter():
    return RequestFormatter(
        '%(name)-13s %(levelname)-8s %(asctime)s '
        '%(server_protocol)s %(method)s %(source)s %(trace_id)s '
        '%(user)s %(path)s %(message)s'
    )


def json_request_formatter():
    return RequestFormatter(
        json.dumps({
            "name": "%(name)s",
            "levelname": "%(levelname)s",
            "asctime": "%(asctime)s",
            "source": "%(source)s",
            "method": "%(method)s",
            "user": "%(user)s",
            "path": "%(path)s",
            "server_protocol": "%(server_protocol)s",
            "message": "%(message)s",
            "trace_id": "%(trace_id)s"
        })
    )


if __name__ == '__main__':
    pass
