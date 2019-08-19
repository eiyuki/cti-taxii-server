#!/usr/bin/env python
import json
import logging

from flask import g, has_request_context, request


class RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.method = request.method
            record.path = request.full_path.rstrip('?')

            source = request.headers.getlist('X-Forwarded-For')
            if request.remote_addr not in source:
                source.append(request.remote_addr)

            record.source = ",".join(source)
        else:
            record.method = '-'
            record.path = '-'

        record.user = getattr(g, 'user', '-')
        return super(RequestFormatter, self).format(record)


def default_request_formatter():
    return RequestFormatter(
        '%(name)s %(levelname)-8s %(asctime)s %(method)s %(source)s %(user)s %(path)s %(message)s'
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
            "message": "%(message)s"
        })
    )


if __name__ == '__main__':
    pass
