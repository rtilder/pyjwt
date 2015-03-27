import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


# Forked from the original. Hopefully we can merge this all back and
# delete this fork. You should consider this package temporary.
setup(
    name = "PyJWT-mozilla",
    version = "0.1.5",
    author = "Jeff Lindsay, Ryan Tilder",
    author_email = "rtilder@mozilla.com",
    description = ("JSON Web Token implementation in Python"),
    license = "MIT",
    keywords = "jwt json web token security signing",
    url = "http://github.com/rtilder/pyjwt",
    packages=['jwt'],
    scripts=['bin/jwt'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
    ],
    install_requires=['M2Crypto'],
)
