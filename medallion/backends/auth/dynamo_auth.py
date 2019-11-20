import codecs
import decimal
import hashlib
import hmac
import json
import logging
import secrets
import time

from flask import request
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


# Helper class to convert a DynamoDB item to JSON.
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if abs(o) % 1 > 0:
                return float(o)
            else:
                return int(o)
        return super(DecimalEncoder, self).default(o)


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
        secret = options.get("hash_secret")
        self.hash_secret_bytes = self._derive_key(secret) if secret else self.secret_bytes

    def set(self, plaintext):
        xjson = not isinstance(plaintext, str)
        pt_bytes = (json.dumps(plaintext, separators=(",", ":")) if xjson else plaintext).encode("utf-8")
        iv_bytes = secrets.token_bytes(self.iv_size)
        aad_bytes = self._digest(iv_bytes + self.secret_bytes, pt_bytes, self.hashing)
        ct_bytes = self._encrypt(self.secret_bytes, pt_bytes, self.algorithm, iv_bytes, aad_bytes)
        hmac_bytes = self._digest(self.secret_bytes, ct_bytes["ct"], self.hashing)

        return {
            "hmac": codecs.encode(hmac_bytes, self.encodeas).decode("utf-8"),
            "ct": codecs.encode(ct_bytes["ct"], self.encodeas).decode("utf-8"),
            "at": codecs.encode(ct_bytes["at"], self.encodeas).decode("utf-8"),
            "aad": codecs.encode(aad_bytes, self.encodeas).decode("utf-8"),
            "iv": codecs.encode(iv_bytes, self.encodeas).decode("utf-8"),
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

    def xfm(self, obj):
        hasher = hashlib.sha256()
        hasher.update(self.hash_secret_bytes)
        hasher.update(obj.encode("utf-8"))
        return hasher.hexdigest()

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
        log.info("Connecting to dynamo at %s", uri or 'AWS')

        dynamodb = boto3.resource("dynamodb", endpoint_url=uri) if uri else boto3.resource("dynamodb")

        self.users_crypto = Crypto({"secret": kwargs["users_secret"]})
        self.users = dynamodb.Table(kwargs["users_table_name"])

        self.api_keys_crypto = Crypto({"secret": kwargs["api_keys_secret"]})
        self.api_keys = dynamodb.Table(kwargs["api_keys_table_name"])

        self.audits_crypto = Crypto({"secret": kwargs["audits_secret"]})
        self.audits = dynamodb.Table(kwargs["audits_table_name"])

    @staticmethod
    def get_item(table, crypto, sid):
        try:
            xid = crypto.xfm(sid)
            r = table.get_item(Key={"xid": xid})
            item = r.get("Item")
            if item is None:
                return None
            ct = item["ct"]
            if ct is None:
                return None
            pt = crypto.get(ct)
            return pt.get("v")
        except ClientError as e:
            log.error("Failed to get item", exc_info=e)
        return None

    def record_user_activity(self, key):
        addrs = request.headers.getlist('X-Forwarded-For')
        if len(addrs) == 0:
            addrs = [request.remote_addr]

        t = int(time.time())
        ct = self.audits_crypto.set({"id": key, "v": {"ip": addrs[0]}})
        response = self.audits.put_item(Item={"xid": self.audits_crypto.xfm(key), "ts": t, "ct": ct})
        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            log.error(json.dumps(response, indent=4, cls=DecimalEncoder))

    def get_password_hash(self, username):
        user = self.get_item(self.users, self.users_crypto, username)
        if user is None:
            return None
        if user.get("status") != "active":
            return None
        self.record_user_activity(username)
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
        self.record_user_activity(api_key_id)
        return user_id
