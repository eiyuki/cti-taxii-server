import copy
import json
import uuid

import six

from medallion import test
from medallion.test.generic_initialize_mongodb import connect_to_client
from medallion.utils import common
from medallion.views import MEDIA_TYPE_STIX_V20, MEDIA_TYPE_TAXII_V20

from .base_test import TaxiiTest


class TestTAXIIServerWithDirectoryBackend(TaxiiTest):
    """
    These tests assume that the './test/directory' contains one sub directory named 'trustgroup1'
    """

    type = "directory"

    @staticmethod
    def load_json_response(response):
        if isinstance(response, bytes):
            response = response.decode()
        io = six.StringIO(response)
        return json.load(io)

    def test_server_discovery(self):
        r = self.client.get(test.DISCOVERY_EP, headers=self.auth)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content_type, MEDIA_TYPE_TAXII_V20)
        server_info = self.load_json_response(r.data)
        assert server_info["title"] == "Indicators from the directory backend"
        assert len(server_info["api_roots"]) == 1
        assert server_info["api_roots"][0] == "http://localhost:5000/trustgroup1/"

    def test_get_api_root_information(self):
        r = self.client.get(test.API_ROOT_EP, headers=self.auth)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content_type, MEDIA_TYPE_TAXII_V20)
        api_root_metadata = self.load_json_response(r.data)
        assert api_root_metadata["title"] == "Indicators from directory \'trustgroup1\'"

    def test_get_collections(self):
        r = self.client.get(test.COLLECTIONS_EP, headers=self.auth)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content_type, MEDIA_TYPE_TAXII_V20)
        collections_metadata = self.load_json_response(r.data)
        collections_metadata = sorted(collections_metadata["collections"], key=lambda x: x["id"])
        collection_ids = [cm["id"] for cm in collections_metadata]

        assert len(collection_ids) == 1
        assert "46bb17fa-0af3-3446-a570-b55cdfdc7881" in collection_ids

    def test_get_collection(self):
        r = self.client.get(test.GET_COLLECTION_EP_FOR_DIRECTORY_BACKEND, headers=self.auth)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content_type, MEDIA_TYPE_TAXII_V20)
        collections_metadata = self.load_json_response(r.data)
        assert collections_metadata["media_types"][0] == "application/vnd.oasis.stix+json; version=2.0"

    def test_get_objects(self):
        r = self.client.get(test.GET_OBJECTS_FROM_DIRECTORY_BACKEND_EP + "?match[type]=indicator", headers=self.auth)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content_type, MEDIA_TYPE_STIX_V20)
        objs = self.load_json_response(r.data)

        self.assertEqual(len(objs["objects"]), 1)
        expected_ids = set(["indicator--7d72d620-9720-4457-897d-7030d1a972df"])
        received_ids = set(obj["id"] for obj in objs["objects"])
        self.assertEqual(expected_ids, received_ids)

    def test_get_object(self):
        r = self.client.get(
            test.GET_OBJECTS_FROM_DIRECTORY_BACKEND_EP + "indicator--7d72d620-9720-4457-897d-7030d1a972df/",
            headers=self.auth,
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content_type, MEDIA_TYPE_STIX_V20)
        obj = self.load_json_response(r.data)
        assert obj["objects"][0]["id"] == "indicator--7d72d620-9720-4457-897d-7030d1a972df"

    def test_add_objects(self):
        pass
