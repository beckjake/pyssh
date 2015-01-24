
from collections import OrderedDict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.constant_time import bytes_eq

from pyssh.base_types import UInt32
from pyssh.constants import (
    ALGORITHM_HMAC_MD5_ETM, ALGORITHM_HMAC_SHA1_ETM, ALGORITHM_HMAC_SHA256_ETM,
    ALGORITHM_HMAC_SHA512_ETM, ALGORITHM_HMAC_SHA1_96_ETM,
    ALGORITHM_HMAC_MD5_96_ETM, ALGORITHM_HMAC_MD5, ALGORITHM_HMAC_SHA1,
    ALGORITHM_HMAC_SHA256, ALGORITHM_HMAC_SHA512, ALGORITHM_HMAC_SHA1_96,
    ALGORITHM_HMAC_MD5_96
)

class InvalidHash(Exception):
    pass


class BaseHasher(object):
    def __init__(self, iv):
        self.iv = iv

    @property
    def digest_size(self):
        """Get the digest size, in bytes."""
        raise NotImplementedError('implement in subclass')

    @property
    def iv_size(self):
        """Get the IV size, in bytes."""
        raise NotImplementedError('implement in subclass')

    def hash(self, data):
        """Hash the given data."""
        raise NotImplementedError('implement in subclass')

    def validate(self, data, mac):
        """Validate the given data."""
        raise NotImplementedError('implement in subclass')


class _CryptographyHasher(BaseHasher):
    def __init__(self, provider, iv, backend=None):
        if backend is None:
            backend = default_backend()
        self._backend = backend
        self._provider = provider
        super(_CryptographyHasher, self).__init__(iv)

    @property
    def digest_size(self):
        return self._provider.digest_size

    @property
    def iv_size(self):
        return self._provider.digest_size

    def hash(self, data):
        hasher = hmac.HMAC(self.iv, self._provider, backend=self._backend)
        hasher.update(data)
        return hasher.finalize()[:self.digest_size]

    def validate(self, data, mac):
        #Because of the truncated mac thing, we can't use real validate().
        hasher = hmac.HMAC(self.iv, self._provider, backend=self._backend)
        hasher.update(data)
        if not bytes_eq(hasher.finalize()[:self.digest_size], mac):
            raise InvalidHash('mac does not match')


class SHA1Hasher(_CryptographyHasher):
    ENCRYPT_FIRST = False
    def __init__(self, iv):
        super(SHA1Hasher, self).__init__(hashes.SHA1(), iv)


class MD5Hasher(_CryptographyHasher):
    ENCRYPT_FIRST = False
    def __init__(self, iv):
        super(MD5Hasher, self).__init__(hashes.MD5(), iv)


# The next 2 are specified in RFC 6668
class SHA256Hasher(_CryptographyHasher):
    ENCRYPT_FIRST = False
    def __init__(self, iv):
        super(SHA256Hasher, self).__init__(hashes.SHA256(), iv)


class SHA512Hasher(_CryptographyHasher):
    ENCRYPT_FIRST = False
    def __init__(self, iv):
        super(SHA512Hasher, self).__init__(hashes.SHA512(), iv)


class SHA1_96Hasher(SHA1Hasher):
    @property
    def digest_size(self):
        return 12


class MD5_96Hasher(MD5Hasher):
    @property
    def digest_size(self):
        return 12


class SHA1ETMHasher(SHA1Hasher):
    ENCRYPT_FIRST = True


class MD5ETMHasher(MD5Hasher):
    ENCRYPT_FIRST = True


class SHA256ETMHasher(SHA256Hasher):
    ENCRYPT_FIRST = True


class SHA512ETMHasher(SHA512Hasher):
    ENCRYPT_FIRST = True


class SHA1_96ETMHasher(SHA1_96Hasher):
    ENCRYPT_FIRST = True


class MD5_96ETMHasher(MD5_96Hasher):
    ENCRYPT_FIRST = True


class NoneHasher(BaseHasher):
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

