from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

import pytest
from io import BytesIO
import unittest

from pyssh.crypto import symmetric
from pyssh.base_types import Direction

class BaseSymmetricTest(object):
    def test_inbound(self):
        inst = self.cls(self.key, self.iv, Direction.inbound)
        assert inst.process_block(self.ciphertext) == self.plaintext
        return inst

    def test_outbound(self):
        inst = self.cls(self.key, self.iv, Direction.outbound)
        assert inst.process_block(self.plaintext) == self.ciphertext
        return inst

    def test_invalid_init(self):
        with pytest.raises(ValueError):
            self.cls(self.key, self.iv, None)

    def test_blocksize(self):
        assert self.cls.block_size == self.block_size

    def test_invalid_keysize(self):
        with pytest.raises(symmetric.InvalidKeySize):
            inst = self.cls(self.key + b'\x00', self.iv, Direction.inbound)



class TestAES_256_CBC(unittest.TestCase, BaseSymmetricTest):
    def setUp(self):
        self.key = b'\x00\x01'*16
        self.iv = b'\x00\x01'*8
        # must be a multiple of 16 chars
        self.plaintext = b'testing: a test\x00'
        self.ciphertext = b'\xD4\xD2\x62\xB3\xE1\x3B\x65\xB3\x25\x27\x31\xEE\x80\x3A\x0A\x46'
        self.cls = symmetric.AES256_CBC
        self.block_size = 16


class TestAES_192_CBC(unittest.TestCase, BaseSymmetricTest):
    def setUp(self):
        self.key = b'\x00\x01'*12
        self.iv = b'\x00\x01'*8
        # must be a multiple of 16 chars
        self.plaintext = b'testing: a test\x00'
        self.ciphertext = b'\x27\x1C\xA7\x34\x0B\xEE\xAF\x05\x3D\x69\x15\xB3\x5E\xBA\xE9\x22'
        self.cls = symmetric.AES192_CBC
        self.block_size = 16

class TestAES_128_CBC(unittest.TestCase, BaseSymmetricTest):
    def setUp(self):
        self.key = b'\x00\x01'*8
        self.iv = b'\x00\x01'*8
        self.plaintext = b'testing: a test\x00'
        self.ciphertext = b'\xE0\x3C\x8F\x62\x51\x84\x80\x03\x76\x1C\x22\x09\x1E\x26\xE2\x25'
        self.cls = symmetric.AES128_CBC
        self.block_size = 16


class TestTripleDES_CBC(unittest.TestCase, BaseSymmetricTest):
    def setUp(self):
        self.key = b'\x00\x01'*12
        self.iv = b'\x00\x01'*4
        self.plaintext = b'testing: a test\x00'
        self.ciphertext = b'\xF6\x2F\x78\x11\x75\x57\x8F\xA7\xEE\x46\xD7\x77\xFF\xDF\x3E\x9D'
        self.cls = symmetric.TripleDES_CBC
        self.block_size = 8


class TestArcfour(unittest.TestCase, BaseSymmetricTest):
    def setUp(self):
        self.key = b'\x00\x01'*8
        self.iv = None
        self.plaintext = b'testing: a test\x00'
        self.ciphertext = b'\x99\x60\x4D\xC6\xDC\x5D\x9F\x04\xE8\x18\x68\x70\xB2\x6B\x3D\xF3'
        self.cls = symmetric.Arcfour
        self.block_size = 8


class TestArcfour128(unittest.TestCase, BaseSymmetricTest):
    def setUp(self):
        self.key = b'\x00\x01'*8
        self.iv = None
        self.plaintext = b'testing: a test\x00'
        self.ciphertext = b'\x09\x0C\x20\xF1\x27\x61\xC0\xE3\x45\xF1\x89\xA5\x09\xDE\x8A\xB5'
        self.cls = symmetric.Arcfour128
        self.block_size = 8


class TestArcfour256(unittest.TestCase, BaseSymmetricTest):
    def setUp(self):
        self.key = b'\x00\x01'*16
        self.iv = None
        self.plaintext = b'testing: a test\x00'
        self.ciphertext = b'\x09\x0C\x20\xF1\x27\x61\xC0\xE3\x45\xF1\x89\xA5\x09\xDE\x8A\xB5'
        self.cls = symmetric.Arcfour256
        self.block_size = 8


class TestNone(unittest.TestCase, BaseSymmetricTest):
    def setUp(self):
        self.key = None
        self.iv = None
        self.plaintext = b'testing: a test\x00'
        self.ciphertext = self.plaintext
        self.cls = symmetric.NoneCipher
        self.block_size = 8

    def test_invalid_keysize(self):
        """Noop test."""

    def test_invalid_init(self):
        """Noop test."""

class TestGetCipher(unittest.TestCase):
    def test_get_ok(self):
        cipher = symmetric.get_cipher(b'aes256-cbc')
        assert cipher is symmetric.AES256_CBC

    def test_get_fail(self):
        with pytest.raises(symmetric.UnsupportedCipherName):
            symmetric.get_cipher(b'nosuch-cipher')




