""" JSON Web Token implementation

Minimum implementation based on this spec:
http://self-issued.info/docs/draft-jones-json-web-token-01.html
"""
import base64
import hashlib
import hmac
import M2Crypto

try:
    import json
except ImportError:
    import simplejson as json
    
__all__ = ['encode', 'decode', 'rsa_load', 'check', 'DecodeError']

class DecodeError(Exception): pass

signing_methods = {
    'HS256': lambda msg, key: hmac.new(unicode(key).encode('utf8'), msg, hashlib.sha256).digest(),
    'HS384': lambda msg, key: hmac.new(unicode(key).encode('utf8'), msg, hashlib.sha384).digest(),
    'HS512': lambda msg, key: hmac.new(unicode(key).encode('utf8'), msg, hashlib.sha512).digest(),
    'RS256': lambda msg, key: key.sign(hashlib.sha256(msg).digest(), 'sha256'),
    'RS384': lambda msg, key: key.sign(hashlib.sha384(msg).digest(), 'sha384'),
    'RS512': lambda msg, key: key.sign(hashlib.sha512(msg).digest(), 'sha512'),
}

verifying_methods = {
    'HS256': lambda msg, key, sig: sig == hmac.new(unicode(key).encode('utf8'), msg, hashlib.sha256).digest(),
    'HS384': lambda msg, key, sig: sig == hmac.new(unicode(key).encode('utf8'), msg, hashlib.sha384).digest(),
    'HS512': lambda msg, key, sig: sig == hmac.new(unicode(key).encode('utf8'), msg, hashlib.sha512).digest(),
    'RS256': lambda msg, key, sig: key.verify(hashlib.sha256(msg).digest(), sig, 'sha256'),
    'RS384': lambda msg, key, sig: key.verify(hashlib.sha384(msg).digest(), sig, 'sha384'),
    'RS512': lambda msg, key, sig: key.verify(hashlib.sha512(msg).digest(), sig, 'sha512')
}


def base64url_decode(input):
    input += '=' * (4 - (len(input) % 4))
    return base64.urlsafe_b64decode(input)

def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace('=', '')

def header(jwt):
    header_segment = jwt.split('.', 1)[0]
    try:
        return json.loads(base64url_decode(header_segment))
    except (ValueError, TypeError):
        raise DecodeError("Invalid header encoding")

def encode(payload, key, algorithm='HS256'):
    segments = []
    header = {"typ": "JWT", "alg": algorithm}
    segments.append(base64url_encode(json.dumps(header)))
    segments.append(base64url_encode(json.dumps(payload)))
    signing_input = '.'.join(segments)
    try:
        signature = signing_methods[algorithm](signing_input, key)
    except KeyError:
        raise NotImplementedError("Algorithm not supported")
    segments.append(base64url_encode(signature))
    return '.'.join(segments)

def decode(jwt, key='', verify=True):
    try:
        signing_input, crypto_segment = jwt.rsplit('.', 1)
        header_segment, payload_segment = signing_input.split('.', 1)
    except ValueError:
        raise DecodeError("Not enough segments")
    try:
        header = json.loads(base64url_decode(header_segment))
        payload = json.loads(base64url_decode(payload_segment))
        signature = base64url_decode(crypto_segment)
    except (ValueError, TypeError):
        raise DecodeError("Invalid segment encoding")
    if verify:
        try:
            if not verifying_methods[header['alg']](signing_input, key, signature):
                raise DecodeError("Signature verification failed")
        except KeyError:
            raise DecodeError("Algorithm not supported")
    return payload

def check(jwt, key=''):
    try:
        decode(jwt, key, True)
        return True
    except:
        return False

def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file."""
    return M2Crypto.RSA.load_key(filename, M2Crypto.util.no_passphrase_callback)

def rsa_load_pub(filename):
    """Read a PEM-encoded RSA pubkey from a file."""
    return M2Crypto.RSA.load_pub_key(filename)
