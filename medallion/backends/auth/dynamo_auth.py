import codecs
import hashlib
import hmac
import json
import logging
import secrets

from werkzeug.security import pbkdf2_bin

from medallion.backends.auth.base import AuthBackend

try:
    import boto3
    from botocore.exceptions import ClientError
    from Crypto.Cipher import AES
except ImportError:
    raise ImportError("'boto3' and 'Pycryptodome' packages are required to use this module.")

# Module-level logger
log = logging.getLogger(__name__)


class Crypto:
    def __init__(self, options):
        self.algorithm = options.get("algorithm", "aes-256-gcm")
        self.hashing = options.get("hashing", "sha256")
        self.key_size = options.get("key_size", 32)
        self.iv_size = options.get("iv_size", 8)
        self.at_size = options.get("at_size", 16)
        self.iterations = options.get("iterations", 15000)
        self.encodeas = "hex"
        self.secret_bytes = self._derive_key(options["secret"])

    def set(self, plaintext):
        xjson = not isinstance(plaintext, str)
        pt_bytes = (json.dumps(plaintext, separators=(":", ",")) if xjson else plaintext).encode("utf-8")
        iv_bytes = secrets.token_bytes(self.iv_size)
        aad_bytes = self._digest(iv_bytes + self.secret_bytes, pt_bytes, self.hashing)
        ct_bytes = self._encrypt(self.secret_bytes, pt_bytes, self.algorithm, iv_bytes, aad_bytes)
        hmac_bytes = self._digest(self.secret_bytes, ct_bytes["ct"], self.hashing)

        return {
            "hmac": codecs.encode(hmac_bytes, self.encodeas),
            "ct": codecs.encode(ct_bytes["ct"], self.encodeas),
            "at": codecs.encode(ct_bytes["at"], self.encodeas),
            "aad": codecs.encode(aad_bytes, self.encodeas),
            "iv": codecs.encode(iv_bytes, self.encodeas),
            "json": xjson
        }

    def get(self, ciphertext):
        ct = ciphertext
        ct_bytes = codecs.decode(ct["ct"], self.encodeas)
        iv_bytes = codecs.decode(ct["iv"], self.encodeas)
        at_bytes = codecs.decode(ct["at"], self.encodeas)
        aad_bytes = codecs.decode(ct["aad"], self.encodeas)
        hmac_bytes = codecs.decode(ct["hmac"], self.encodeas)

        calculated_hmac_bytes = self._digest(self.secret_bytes, ct_bytes, self.hashing)
        if hmac_bytes != calculated_hmac_bytes:
            raise ValueError("Encrypted session was tampered with!")

        pt = self._decrypt(self.secret_bytes, ct_bytes, self.algorithm, iv_bytes, at_bytes, aad_bytes)
        return json.loads(pt) if ct["json"] else pt

    @staticmethod
    def _digest(key, obj, hashing):
        return hmac.digest(key, obj, hashing)

    def _encrypt(self, key, pt, algo, iv, aad):
        if algo == "aes-256-gcm":
            aes = AES.new(key, AES.MODE_GCM, iv, mac_len=self.at_size)
            aes.update(aad)
            ct, at = aes.encrypt_and_digest(pt)
            return {"ct": ct, "at": at}
        else:
            raise ValueError("unknown algorithm")

    def _decrypt(self, key, ct, algo, iv, at, aad):
        if algo == "aes-256-gcm":
            aes = AES.new(key, AES.MODE_GCM, iv, mac_len=self.at_size)
            aes.update(aad)
            pt = aes.decrypt_and_verify(ct, at)
            return pt
        else:
            raise ValueError("unknown algorithm")

    def _derive_key(self, secret):
        if self.hashing == "sha256":
            hasher = hashlib.sha256()
            hasher.update(secret.encode("utf-8"))

            salt = hasher.hexdigest()[0:self.iv_size]

            key = pbkdf2_bin(secret, salt, self.iterations, self.key_size, self.hashing)

            return key[0:self.key_size] if len(key) > self.key_size else key
        else:
            raise ValueError("unknown hash")


class AuthDynamoBackend(AuthBackend):
    def __init__(self, uri, **kwargs):
        dynamodb = boto3.resource("dynamodb") if uri is None else boto3.resource("dynamodb", endpoint_url=uri)

        self.users_crypto = Crypto({"secret": kwargs["users_secret"]})
        self.users = dynamodb.Table(kwargs["users_table_name"])
        self.username_column = kwargs["users_table_key"]

        self.api_keys_crypto = Crypto({"secret": kwargs["api_keys_secret"]})
        self.api_keys = dynamodb.Table(kwargs["api_keys_table_name"])
        self.api_key_column = kwargs["api_keys_table_key"]

    @staticmethod
    def get_item(table, crypto, sid):
        try:
            r = table.get_item(Key={"sid": sid})
            item = r.get("Item")
            return None if item is None else crypto.get(item["inf"])
        except ClientError as e:
            log.error("Failed to get item", exc_info=e)
        return None

    def get_password_hash(self, username):
        user = self.get_item(self.users, self.users_crypto, username)
        if user is None:
            return None
        if user.get("status") != "active":
            return None
        return user.get("password")

    def get_username_for_api_key(self, api_key_id):
        apikey = self.get_item(self.api_keys, self.api_keys_crypto, api_key_id)
        if apikey is None:
            return None
        user_id = apikey.get("user_id")
        if user_id is None:
            return None
        user = self.get_item(self.users, self.users_crypto, user_id)
        if user is None:
            return None
        if user.get("status") != "active":
            return None
        return user_id
