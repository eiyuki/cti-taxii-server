import unittest

from medallion.backends.auth.dynamo_auth import Crypto


class MyTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.crypto = Crypto({"secret": "bob's your uncle"})

    def test_encrypt_with_random_iv(self):
        pta = "test"
        ct = self.crypto.set(pta)
        ptb = self.crypto.get(ct)
        self.assertEqual(pta, ptb)

    def test_decrypt_my_ct(self):
        ct = {
            "hmac": "9dff245be413b5bbe5c78be31597c0be66a7eb84cb8c012436e280449fc11c3c",
            "ct": "91cdfd5b",
            "at": "72f0b5fc70209dac057feb5d83f2a0d3",
            "aad": "64e3df4eba8515aa5fa2d32f7cc4d0ac9b310f0761dfab06c88be8176118564e",
            "iv": "3132333435363738",
            "json": False
        }
        pt = self.crypto.get(ct)
        self.assertEqual("test", pt)


if __name__ == '__main__':
    unittest.main()
