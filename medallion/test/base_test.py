import os
import unittest

from medallion import create_app
from medallion.test import config as test_configs
from medallion.test.data.initialize_mongodb import reset_db


class TaxiiTest(unittest.TestCase):
    type = None
    DATA_FILE = os.path.join(
        os.path.dirname(__file__), "data", "default_data.json")
    API_OBJECTS_2 = {
        "id": "bundle--8fab937e-b694-11e3-b71c-0800271e87d2",
        "objects": [
            {
                "created": "2017-01-27T13:49:53.935Z",
                "id": "indicator--%s",
                "labels": [
                    "url-watchlist",
                ],
                "modified": "2017-01-27T13:49:53.935Z",
                "name": "Malicious site hosting downloader",
                "pattern": "[url:value = 'http://x4z9arb.cn/5000']",
                "type": "indicator",
                "valid_from": "2017-01-27T13:49:53.935382Z",
            },
        ],
        "spec_version": "2.0",
        "type": "bundle",
    }

    memory_config = test_configs.memory_config(DATA_FILE)
    directory_config = test_configs.directory_config()
    mongodb_config = test_configs.mongodb_config()

    def setUp(self):
        if self.type == "mongo":
            reset_db()
            self.configuration = self.mongodb_config
        elif self.type == "memory":
            self.memory_config['backend']['filename'] = self.DATA_FILE
            self.configuration = self.memory_config
        elif self.type == "directory":
            self.configuration = self.directory_config
        else:
            raise RuntimeError("Unknown backend!")

        self.app = create_app(self.configuration)
        self.app_context = self.app.app_context()
        self.app_context.push()

        # TODO: It might be better to not reuse the test client.
        self.client = self.app.test_client()
        self.auth = {'Authorization': 'Token abc123'}

    def tearDown(self):
        self.app_context.pop()
