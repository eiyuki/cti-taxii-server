import json
import os
import uuid

from medallion.exceptions import ProcessingError
from medallion.filters.basic_filter import BasicFilter
from medallion.utils.common import (create_bundle, format_datetime,
                                    generate_status, get_timestamp, iterpath)

from .base import Backend


class DirectoryBackend(Backend):
    # access control is handled at the views level

    def __init__(self, path=None, **kwargs):
        self.path = path
        self.discovery_config = self.init_discovery_config(kwargs.get('discovery', None))
        self.api_root_config = self.init_api_root_config(kwargs.get('api-root', None))
        self.collection_config = self.init_collection_config(kwargs.get('collection', None))
        self.statuses = []

    # noinspection PyMethodMayBeStatic
    def init_discovery_config(self, discovery_config):
        if not self.path:
            raise ProcessingError("path was not specified in the config file")

        dc = discovery_config

        if dc.get('default', None):
            if dc.get('api_roots', None):
                if not dc['default'] in dc['api_roots']:
                    raise ProcessingError("The default api root '{}' was not found in api_roots".format(dc['default']))
            else:
                raise ProcessingError("api_roots was not specified in the config file".format(dc['default']))
        else:
            raise ProcessingError("discovery was not specified in the config file")

        if not os.path.isdir(self.path):
            raise ProcessingError("Directory '{}' was not found".format(self.path))

        collection_dirs = [f for f in os.listdir(self.path) if os.path.isdir(os.path.join(self.path, f))]
        collection_dirs_len = len(collection_dirs)

        if collection_dirs_len == 0:
            raise ProcessingError("No directories were found in path '{}'".format(self.path))

        # if collection_dirs_len != len(dc['api_roots']):
        #     raise ProcessingError("The # of api_roots != the # of directories in path '{}'".format(self.path))

        return dc

    def update_discovery_config(self):
        dc = self.discovery_config
        collection_dirs = [f for f in os.listdir(self.path) if os.path.isdir(os.path.join(self.path, f))]

        # If there are new directories not in api_roots, add them in
        host_port = dc['default'].rsplit('/', 2)[0]

        updated_roots = ['{}/{}/'.format(host_port, f) for f in collection_dirs]

        if self.discovery_config['default'] in updated_roots:
            self.discovery_config['api_roots'] = updated_roots
        else:
            raise ProcessingError("The default api root '{}' was not found in api_roots".format(dc['default']))

    # noinspection PyMethodMayBeStatic
    def init_api_root_config(self, api_root_config):
        if api_root_config:
            return api_root_config
        else:
            raise ProcessingError("api-root was not specified in the config file")

    # noinspection PyMethodMayBeStatic
    def init_collection_config(self, collection_config):
        if collection_config:
            return collection_config
        else:
            raise ProcessingError("collection was not specified in the config file")

    def server_discovery(self):
        self.update_discovery_config()
        return self.discovery_config

    def get_api_root_information(self, api_root):
        self.update_discovery_config()

        api_roots = self.discovery_config['api_roots']

        for r in api_roots:
            c_dir = r.rsplit('/', 2)[1]

            if api_root == c_dir:
                i_title = "Indicators from directory '{}'".format(c_dir)

                i = {
                    "title": i_title,
                    "description": "",
                    "versions": self.api_root_config['versions'],
                    "max-content-length": self.api_root_config['max-content-length']
                }

                return i

    def get_collections(self, api_root):
        self.update_discovery_config()

        api_roots = self.discovery_config['api_roots']

        collections = []

        # Generate a collection object for each api_root
        for r in api_roots:
            c_dir = r.rsplit('/', 2)[1]
            c_id = uuid.uuid3(uuid.NAMESPACE_URL, r)
            c_title = "Indicators from directory '{}'".format(c_dir)

            c = {
                "id": str(c_id),
                "title": c_title,
                "description": self.collection_config['description'],
                "can_read": self.collection_config['can_read'],
                "can_write": self.collection_config['can_write'],
                "media_types": self.collection_config['media_types']
            }

            collections.append(c)

        return collections

    def get_collection(self, api_root, collection_id):
        collections = self.get_collections(api_root)

        for c in collections:
            if 'id' in c and collection_id == c['id']:
                return c

    def get_objects_without_bundle(self, api_root, collection_id, filter_args, allowed_filters):
        self.update_discovery_config()
        api_roots = self.discovery_config['api_roots']

        host_port = self.discovery_config['default'].rsplit('/', 2)[0]

        full_api_root = '{}/{}/'.format(host_port, api_root)

        if full_api_root in api_roots:
            # Get the collection
            collection = None
            collections = self.get_collections(api_root)

            for c in collections:
                if 'id' in c and collection_id == c['id']:
                    collection = c
                    break

            if not collection:
                raise ProcessingError("collection for api-root '{}' was not found".format(api_root))

            # Get the objects for the collection

            p = os.path.join(self.path, api_root)

            files = [f for f in os.listdir(p) if os.path.isfile(os.path.join(p, f)) and f.endswith('.json')]

            objects = []

            for f in files:
                with open(os.path.join(p, f), "r") as rawJson:
                    stix2 = json.load(rawJson)

                    if stix2.get('type', '') == 'bundle' and stix2.get('spec_version', '') == '2.0':
                        bundle_objects = stix2.get('objects', [])
                        if len(bundle_objects):
                            objects.extend(bundle_objects)
                    else:
                        continue
                        # raise ProcessingError("no stix2 bundle was found in file '{}'".format(f))

            # Add the objects to the collection

            collection['objects'] = objects

            # Filter the collection

            filtered_objects = []

            if filter_args:
                full_filter = BasicFilter(filter_args)
                filtered_objects.extend(
                    full_filter.process_filter(
                        collection.get("objects", []),
                        allowed_filters,
                        collection.get("manifest", [])
                    )
                )
            else:
                filtered_objects.extend(collection.get("objects", []))

            return filtered_objects

    def get_objects(self, api_root, collection_id, filter_args, allowed_filters):
        objects = self.get_objects_without_bundle(api_root, collection_id, filter_args, allowed_filters)

        return create_bundle(objects)

    def get_object(self, api_root, collection_id, object_id, filter_args, allowed_filters):
        objects = self.get_objects_without_bundle(api_root, collection_id, filter_args, allowed_filters)

        req_object = filter(lambda x: x['id'] == object_id, objects)

        if len(req_object) == 1:
            return req_object[0]

    def get_object_manifest(self, api_root, collection_id, filter_args, allowed_filters):
        self.update_discovery_config()
        api_roots = self.discovery_config['api_roots']

        host_port = self.discovery_config['default'].rsplit('/', 2)[0]

        full_api_root = '{}/{}/'.format(host_port, api_root)

        if full_api_root in api_roots:
            collections = self.get_collections(api_root)

            for collection in collections:
                if "id" in collection and collection_id == collection["id"]:
                    manifest = collection.get("manifest", [])
                    if filter_args:
                        full_filter = BasicFilter(filter_args)
                        manifest = full_filter.process_filter(
                            manifest,
                            allowed_filters,
                            None
                        )
                    return manifest

    def add_objects(self, api_root, collection_id, objs):
        """
        Fill:

            implement the add_objects TAXII endpoint by save data into a collection

        Args:

            api_root (str): the name of the api_root.

            collection_id (str): the id of the collection

            objs (list):  objects to insert into the collection

        Returns:

            status of the request (including):
                how many objects were successful saved
                how many objects failed to be saved
                how many objects are pending

        METADATA ABOUT EACH SUCCESSFUL OBJECT SAVED MUST BE AVAILABLE VIA THE get_object_manifest API CALL
        THIS CAN BE IMPLEMENTED AS A SEPARATE STORE, OTHERWISE IT NEEDS TO BE GENERATABLE DYNAMICALLY

        """
        raise NotImplementedError()

    def get_status(self, api_root, status_id):
        """
        Fill:

            implement the get_status TAXII endpoint by obtaining the status of an add_objects request

        Args:

            api_root (str): the name of the api_root.

            status_id (str): the id of the add_objects request

        Returns:

            status of the request (including):
                how many objects were successful saved
                how many objects failed to be saved
                how many objects are pending

        """
        raise NotImplementedError()
