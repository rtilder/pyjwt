""" JSON Web Token implementation

Minimum implementation based on this spec:
http://self-issued.info/docs/draft-jones-json-web-token-01.html
"""
import base64
import hashlib
import hmac
import logging
import M2Crypto

try:
    import json
except ImportError:
    import simplejson as json

__all__ = ['encode', 'decode', 'rsa_load', 'check', 'DecodeError']

log = logging.getLogger(__name__)

class DecodeError(Exception): pass
class EncodeError(Exception): pass

signing_methods = {
    'HS256': lambda msg, key: hmac.new(key, msg, hashlib.sha256).digest(),
    'HS384': lambda msg, key: hmac.new(key, msg, hashlib.sha384).digest(),
    'HS512': lambda msg, key: hmac.new(key, msg, hashlib.sha512).digest(),
    'RS256': lambda msg, key: key.sign(hashlib.sha256(msg).digest(), 'sha256'),
    'RS384': lambda msg, key: key.sign(hashlib.sha384(msg).digest(), 'sha384'),
    'RS512': lambda msg, key: key.sign(hashlib.sha512(msg).digest(), 'sha512'),
    'none': lambda msg, key: '',
}

verifying_methods = {
    'HS256': lambda msg, key, sig: equiv(sig, hmac.new(key, msg, hashlib.sha256).digest()),
    'HS384': lambda msg, key, sig: equiv(sig, hmac.new(key, msg, hashlib.sha384).digest()),
    'HS512': lambda msg, key, sig: equiv(sig, hmac.new(key, msg, hashlib.sha512).digest()),
    'RS256': lambda msg, key, sig: key.verify(hashlib.sha256(msg).digest(), sig, 'sha256'),
    'RS384': lambda msg, key, sig: key.verify(hashlib.sha384(msg).digest(), sig, 'sha384'),
    'RS512': lambda msg, key, sig: key.verify(hashlib.sha512(msg).digest(), sig, 'sha512'),
    'none': lambda msg, key, sig: check_none_verify(msg, key, sig)
}

SUPPORTED_ALGOS = tuple(verifying_methods.keys())
ALLOWED_ALGOS = sorted(SUPPORTED_ALGOS)
# Remove the 'none' type from our particular usage
del ALLOWED_ALGOS[len(ALLOWED_ALGOS) - 1] 
ALLOWED_ALGOS = tuple(ALLOWED_ALGOS)

def check_none_verify(msg, key, sig):
    """
    If there is a signature included with a alg=none header then the
    verification should fail
    """
    if sig:
        return False
    return True

# Based on
# http://rdist.root.org/2010/01/07/timing-independent-array-comparison/
def equiv(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

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

def encode(payload, key, algorithm='HS256', header=None, encoder=None):
    segments = []
    if header is None:
        header = {"typ": "JWT", "alg": algorithm}
    else:
        if not header.has_key('typ'):
            raise EncodeError('Missing "typ" header in custom headers')
        if not header.has_key('alg'):
            header['alg'] = algorithm
    segments.append(base64url_encode(json.dumps(header)))
    # Allow custom JSON encodings.
    segments.append(base64url_encode(json.dumps(payload, cls=encoder)))
    signing_input = '.'.join(segments)
    try:
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        signature = signing_methods[algorithm](signing_input, key)
    except KeyError:
        raise NotImplementedError("Algorithm not supported")
    segments.append(base64url_encode(signature))
    return '.'.join(segments)

def decode(jwt, key='', verify=True, algorithms=None):
    if algorithms is not None:
        if type(algorithms) not in (list, tuple):
            raise ValueError("algorithms must be a list or tuple")
    else:
        algorithms = ALLOWED_ALGOS
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
        # Log the actual exception so you know what's going on.
        log.debug('Could not decode a segment', exc_info=True)
        raise DecodeError("Invalid segment encoding")
    if verify:
        if header['alg'] not in algorithms:
            raise DecodeError("Algorithm not allowed")
        try:
            if isinstance(key, unicode):
                key = key.encode('utf-8')
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

def set_algorithms(*args):
    global ALLOWED_ALGOS

    old = tuple(ALLOWED_ALGOS)
    new = []
    for algo in args:
        if algo not in SUPPORTED_ALGOS:
            raise ValueError("Unsupported algorithm \"%s\"" % algo)
        if algo not in new:
            new.append(algo)
    ALLOWED_ALGOS = new
    return old
