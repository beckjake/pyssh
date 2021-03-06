"""An implementation of hashing algorithms specified in the various RFCs.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from collections import OrderedDict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.constant_time import bytes_eq

from pyssh.base_types import classproperty
from pyssh.constants import (
    ALGORITHM_HMAC_MD5_ETM, ALGORITHM_HMAC_SHA1_ETM, ALGORITHM_HMAC_SHA256_ETM,
    ALGORITHM_HMAC_SHA512_ETM, ALGORITHM_HMAC_SHA1_96_ETM,
    ALGORITHM_HMAC_MD5_96_ETM, ALGORITHM_HMAC_MD5, ALGORITHM_HMAC_SHA1,
    ALGORITHM_HMAC_SHA256, ALGORITHM_HMAC_SHA512, ALGORITHM_HMAC_SHA1_96,
    ALGORITHM_HMAC_MD5_96
)

# pylint:disable=too-few-public-methods

class InvalidHash(Exception):
    """The hash given was invalid."""


class BaseHasher(object):
    """The base class for all hasher objects."""
    def __init__(self, iv):
        self.iv = iv  #pylint: disable=invalid-name

    @classproperty
    def digest_size(cls):
        """Get the digest size, in bytes."""
        raise NotImplementedError('implement in subclass')

    @classproperty
    def iv_size(cls):
        """Get the IV size, in bytes."""
        raise NotImplementedError('implement in subclass')

    def hash(self, data):
        """Hash the given data."""
        raise NotImplementedError('implement in subclass')

    def validate(self, data, mac):
        """Validate the given data."""
        raise NotImplementedError('implement in subclass')


class _CryptographyHasher(BaseHasher):
    """An internal-only class that all cryptography-based hashers should derive
    from.
    """
    PROVIDER = None
    def __init__(self, iv, backend=None):
        if backend is None:
            backend = default_backend()
        self._backend = backend
        super(_CryptographyHasher, self).__init__(iv)

    @classproperty
    def digest_size(cls):
        return cls.PROVIDER.digest_size

    @classproperty
    def iv_size(cls):
        return cls.PROVIDER.digest_size

    def hash(self, data):
        hasher = hmac.HMAC(self.iv, self.PROVIDER, backend=self._backend)
        hasher.update(data)
        return hasher.finalize()[:self.digest_size]

    def validate(self, data, mac):
        #Because of the truncated mac thing, we can't use real validate().
        hasher = hmac.HMAC(self.iv, self.PROVIDER, backend=self._backend)
        hasher.update(data)
        hashed = hasher.finalize()[:self.digest_size]
        if not bytes_eq(hashed, mac):
            raise InvalidHash('mac does not match')


class SHA1Hasher(_CryptographyHasher):
    """SHA1 hash, full length digest."""
    ENCRYPT_FIRST = False
    PROVIDER = hashes.SHA1()
    def __init__(self, iv):
        super(SHA1Hasher, self).__init__(iv)


class MD5Hasher(_CryptographyHasher):
    """MD5 hash, full length digest."""
    ENCRYPT_FIRST = False
    PROVIDER = hashes.MD5()
    def __init__(self, iv):
        super(MD5Hasher, self).__init__(iv)


class SHA1_96Hasher(SHA1Hasher): #pylint: disable=invalid-name
    """SHA1 hash, short digest."""
    @classproperty
    def digest_size(cls):
        return 12


class MD5_96Hasher(MD5Hasher): #pylint: disable=invalid-name
    """MD5 hash, short digest."""
    @classproperty
    def digest_size(cls):
        return 12


class NoneHasher(BaseHasher):
    """The 'none' hash used before kex."""
    ENCRYPT_FIRST = False
    def __init__(self, iv=None):
        super(NoneHasher, self).__init__(iv)

    @property
    def digest_size(self):
        return 0

    @property
    def iv_size(self):
        return 0

    def hash(self, data):
        return b''

    def validate(self, data, mac):
        pass


# The next 2 are specified in RFC 6668
class SHA256Hasher(_CryptographyHasher):
    """256-bit SHA2 hash"""
    ENCRYPT_FIRST = False
    PROVIDER = hashes.SHA256()
    def __init__(self, iv):
        super(SHA256Hasher, self).__init__(iv)


class SHA512Hasher(_CryptographyHasher):
    """512-bit SHA2 hash"""
    ENCRYPT_FIRST = False
    PROVIDER = hashes.SHA512()
    def __init__(self, iv):
        super(SHA512Hasher, self).__init__(iv)


# From Openssh.
class SHA1ETMHasher(SHA1Hasher):
    """SHA1 hash, full-length digest, encrypt-then-mac"""
    ENCRYPT_FIRST = True


class MD5ETMHasher(MD5Hasher):
    """MD5 hash, full-length digest, encrypt-then-mac"""
    ENCRYPT_FIRST = True


class SHA1_96ETMHasher(SHA1_96Hasher): #pylint: disable=invalid-name
    """SHA1 hash, short digest, encrypt-then-mac"""
    ENCRYPT_FIRST = True


class MD5_96ETMHasher(MD5_96Hasher): #pylint: disable=invalid-name
    """SHA1 hash, short digest, encrypt-then-mac"""
    ENCRYPT_FIRST = True


class SHA256ETMHasher(SHA256Hasher):
    """256-bit SHA2 hash, encrypt-then-mac"""
    ENCRYPT_FIRST = True


class SHA512ETMHasher(SHA512Hasher):
    """512-bit SHA2 hash, encrypt-then-mac"""
    ENCRYPT_FIRST = True


# this is the order openssh does it (I think), which is good enough for me
HASHES = OrderedDict((
    (ALGORITHM_HMAC_MD5_ETM, MD5ETMHasher),
    (ALGORITHM_HMAC_SHA1_ETM, SHA1ETMHasher),
    (ALGORITHM_HMAC_SHA256_ETM, SHA256ETMHasher),
    (ALGORITHM_HMAC_SHA512_ETM, SHA512ETMHasher),
    (ALGORITHM_HMAC_MD5_96_ETM, SHA1_96ETMHasher),
    (ALGORITHM_HMAC_SHA1_96_ETM, MD5_96ETMHasher),
    (ALGORITHM_HMAC_MD5, MD5Hasher),
    (ALGORITHM_HMAC_SHA1, SHA1Hasher),
    (ALGORITHM_HMAC_SHA256, SHA256Hasher),
    (ALGORITHM_HMAC_SHA512, SHA512Hasher),
    (ALGORITHM_HMAC_MD5_96, MD5_96Hasher),
    (ALGORITHM_HMAC_SHA1_96, SHA1_96Hasher)
))


def get_hasher(algorithm):
    """Given the algorithm, get its hasher."""
    try:
        hasher = HASHES[algorithm]
    except KeyError:
        raise ValueError('Invalid algorithm: {}'.format(algorithm))
    return hasher

