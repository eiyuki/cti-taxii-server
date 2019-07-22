#!/usr/bin/env python


def _base_config(backend):
    return {
        'SECRET_KEY': 'testsecret',
        'TESTING': True,
        'backend': backend,
        'AUTH': ['api_key', 'jwt', 'basic'],
        "users": {
            "admin": "pbkdf2:sha256:150000$xaVt57AC$6edb6149e820fed48495f21bcf98bcc8663cd413bbd97b91d72c671f8f445bea"
        },
        "api_keys": {
            "abc123": "admin",
        },
        "taxii": {
            "max_page_size": 20
        }
    }


def memory_config(data_file):
    return _base_config({
        "module": "medallion.backends.memory_backend",
        "module_class": "MemoryBackend",
        "filename": data_file
    })


def mongodb_config():
    return _base_config({
        "module": "medallion.backends.mongodb_backend",
        "module_class": "MongoBackend",
        "uri": "mongodb://localhost:27017/"
    })


if __name__ == '__main__':
    pass
