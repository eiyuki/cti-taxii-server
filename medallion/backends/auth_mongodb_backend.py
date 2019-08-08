import logging

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from medallion.backends.auth_base import AuthBackend

# Module-level logger
log = logging.getLogger(__name__)


class AuthMongodbBackend(AuthBackend):
    def __init__(self, uri, db_name, **kwargs):
        try:
            self.client = MongoClient(uri)
            self.db_name = db_name
            # The ismaster command is cheap and does not require auth.
            # self.client.admin.command("ismaster")
        except ConnectionFailure:
            log.error("Unable to establish a connection to MongoDB server {}".format(uri))

    def get_password_hash(self, username):
        db = self.client[self.db_name]
        users = db['users']
        user_obj = users.find_one({"_id": username})
        if user_obj:
            return user_obj['password']
        else:
            return None

    def get_username_for_api_key(self, api_key):
        db = self.client[self.db_name]
        api_keys = db['api_keys']
        api_key_obj = api_keys.find_one({"_id": api_key})

        if api_key_obj:
            username = api_key_obj['user_id']
            return username
        else:
            return None