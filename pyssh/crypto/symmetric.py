from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from collections import OrderedDict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from pyssh.base_types import classproperty, String, MPInt, Direction


class InvalidKeySize(Exception):
    """Wrong key size."""
    def __init__(self, expected, got):
        self.expected = expected
        self.got = got
        message = 'Expected key size of {}, got key of size {}'.format(expected, got)
        super(InvalidKeySize, self).__init__(message, expected, got)


class UnsupportedCipherName(Exception):
    """Cipher not supported by get_cipher."""

class BaseCipher(object):
    NAME = None
    KEY_SIZE = None
    def process_block(self, data):
        raise NotImplementedError('not implemented')

    @classproperty
    def block_size(cls):
        return 8


class _CryptographyCipher(BaseCipher):
    ALGORITHM = None
    MODE = None
    def __init__(self, key, iv, direction):
        mode = self.MODE(iv) if self.MODE else None
        if len(key) != self.KEY_SIZE:
            raise InvalidKeySize(self.KEY_SIZE, len(key))

        algorithm = self.ALGORITHM(key)
        self.cipher = Cipher(algorithm, mode, backend=default_backend())
        if direction is Direction.outbound:
            self.converter = self.cipher.encryptor()
        elif direction is Direction.inbound:
            self.converter = self.cipher.decryptor()
        else:
            raise ValueError("must be inbound or outbound")

    @classproperty
    def block_size(cls):
        """Get the block size in bytes."""
        try:
            return max((cls.ALGORITHM.block_size // 8, 8))
        except AttributeError:
            return super(_CryptographyCipher, cls).block_size

    def process_block(self, data):
        return self.converter.update(data)


class AES_CBC(_CryptographyCipher):
    ALGORITHM = algorithms.AES
    MODE = modes.CBC


class AES256_CBC(AES_CBC):
    NAME = 'aes256-cbc'
    KEY_SIZE = 32


class AES192_CBC(AES_CBC):
    NAME = 'aes192-cbc'
    KEY_SIZE = 24


class AES128_CBC(AES_CBC):
    NAME = 'aes128-cbc'
    KEY_SIZE = 16


class TripleDES_CBC(_CryptographyCipher):
    NAME = '3des-cbc'
    KEY_SIZE = 24
    ALGORITHM = algorithms.TripleDES
    MODE = modes.CBC


# This is a terrible algorithm and you should not use it. Instead, use
# 'arcfour128' or 'arcfour256'.
class Arcfour(_CryptographyCipher):
    Name = 'arcfour'
    KEY_SIZE = 16
    ALGORITHM = algorithms.ARC4


#RFC 4345
class _ImprovedArcfour(_CryptographyCipher):
    ALGORITHM = algorithms.ARC4
    def __init__(self, key, iv, direction):
        super(_ImprovedArcfour, self).__init__(key, iv, direction)
        self.process_block(1536*b'\x00')


class Arcfour128(_ImprovedArcfour):
    NAME = 'arcfour128'
    KEY_SIZE = 16


class Arcfour256(_ImprovedArcfour):
    NAME = 'arcfour256'
    KEY_SIZE = 32


class NoneCipher(BaseCipher):
    NAME = 'none'
    def __init__(self, key, iv, direction):
        pass

    def process_block(self, data):
        return data


CIPHERS = OrderedDict((
    (b'aes256-cbc', AES256_CBC),
    (b'aes192-cbc', AES192_CBC),
    (b'aes128-cbc', AES128_CBC),
    (b'3des-cbc', TripleDES_CBC),
    (b'arcfour256', Arcfour256),
    (b'arcfour128', Arcfour128)
))


def get_cipher(ciphername):#, direction, key=None, iv=None):
    try:
        cipher = CIPHERS[ciphername]
    except KeyError:
        raise UnsupportedCipherName(ciphername)
    # return cipher(key, iv, direction)
    return cipher

