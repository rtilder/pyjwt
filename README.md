PyJWT-mozilla
=============

A Python implementation of [JSON Web Token draft 01](http://self-issued.info/docs/draft-jones-json-web-token-01.html).

This is Mozilla's fork of [PyJWT](http://pypi.python.org/pypi/PyJWT)
which adds RSA algorithms, fixes some timing
attacks, and makes a few other adjustments. It is used in projects such as
[webpay](https://github.com/mozilla/webpay).

Installing
----------

Install the module with [pip](http://www.pip-installer.org/) or something similar:

    pip install PyJWT-mozilla

This install step will also install/compile
[M2Crypto](http://pypi.python.org/pypi/M2Crypto)
so you will need `swig` for this. You can get it with a package manager like:

    brew install swig

Alternatively you can probably find a binary package for M2Crypto with
something like this:

   sudo apt-get install python-m2crypto


Usage
-----

    import jwt
    jwt.encode({"some": "payload"}, "secret")

Note the resulting JWT will not be encrypted, but verifiable with a secret key.

    jwt.decode("someJWTstring", "secret")

If the secret is wrong, it will raise a `jwt.DecodeError` telling you as such. You can still get at the payload by setting the verify argument to false.

    jwt.decode("someJWTstring", verify=False)

Algorithms
----------

The JWT spec supports several algorithms for cryptographic signing. This library currently supports:

* HS256	- HMAC using SHA-256 hash algorithm (default)
* HS384	- HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm
* RS256 - RSA using SHA-256 hash algorithm
* RS384 - RSA using SHA-384 hash algorithm
* RS512 - RSA using SHA-584 hash algorithm

Change the algorithm with by setting it in encode:

    jwt.encode({"some": "payload"}, "secret", "HS512")

Tests
-----

Install the project in a [virtualenv](http://pypi.python.org/pypi/virtualenv)
(or wherever) by typing this from the root:

    python setup.py develop

Run the tests like this:

    python tests/test_jwt.py

License
-------

MIT
