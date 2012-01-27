import os
import unittest
import time

import jwt

class TestJWT(unittest.TestCase):

    def setUp(self):
        self.payload = {"iss": "jeff", "exp": int(time.time()), "claim": "insanity"}

    def test_encode_decode(self):
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)
    
    def test_bad_secret(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)
        self.assertRaises(jwt.DecodeError, jwt.decode, jwt_message, bad_secret)
    
    def test_decodes_valid_jwt(self):
        example_payload = {"hello": "world"}
        example_secret = "secret"
        example_jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8"
        decoded_payload = jwt.decode(example_jwt, example_secret)
        self.assertEqual(decoded_payload, example_payload)
    
    def test_allow_skip_verification(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)
        decoded_payload = jwt.decode(jwt_message, verify=False)
        self.assertEqual(decoded_payload, self.payload)

    def test_bad_segments(self):
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret) + 'garbage'
        self.assertRaises(jwt.DecodeError,
                          jwt.decode, jwt_message, key=secret)

    def test_no_secret(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)
        self.assertRaises(jwt.DecodeError, jwt.decode, jwt_message)
    
    def test_invalid_crypto_alg(self):
        self.assertRaises(NotImplementedError, jwt.encode, self.payload, "secret", "HS1024")
    
    def test_unicode_secret(self):
        secret = u'\xc2'
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)
    
    def test_rsa_encode(self):
        root = os.path.dirname(__file__)
        pubkey = jwt.rsa_load_pub(os.path.join(root, "rsapubkey.pem"))
        
        jwt.decode(b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw", 
            pubkey)
        
        key = jwt.rsa_load(os.path.join(root, "rsakey.pem"))
        # Example from the JWS spec
        assert jwt.check(b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw", key)
        assert not jwt.check(b"eyJhbGciOiJSUzI1NiJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw", key)

        # XXX Should test the Signer classes directly. The check(encode()) dance
        # doesn't really verify that the correct algorithm was used, or that the
        # algorithm was implemented properly.
        assert jwt.check(jwt.encode(u"test", key, u'RS256'), key)
        assert jwt.check(jwt.encode(u"test", key, u'RS384'), key)
        assert jwt.check(jwt.encode(u"test", key, u'RS512'), key)




if __name__ == '__main__':
    unittest.main()