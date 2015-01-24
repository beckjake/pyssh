from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

import pytest
import unittest
from pyssh.crypto import hashers


class TestHashes(unittest.TestCase):
    def _check_data(self, cls, iv, data, expect):
        assert cls(iv).hash(data) == expect
        cls(iv).validate(data, expect)

    def test_sha1(self):
        expect = (b'\x72\xD2\x24\xD3\x42\x63\x87\x22\x96\x5F\xA0\xDF'
                  b'\x99\x7F\x91\xAB\x2E\x9E\xD9\x4D')
        iv = b'\x00'*20
        self._check_data(hashers.SHA1Hasher, iv, b'test', expect)
        inst = hashers.SHA1Hasher(iv)
        assert inst.iv_size == 20
        assert inst.digest_size == 20
        with pytest.raises(hashers.InvalidHash):
            inst.validate(b'asdf', expect)

    def test_md5(self):
        expect = (b'\xE2\x83\x4E\x84\xB6\xAD\x91\x74\x5B\x22\xFC\xB3\x2F\xAE'
                  b'\x50\x96')
        iv = b'\x00'*16
        self._check_data(hashers.MD5Hasher, iv, b'test', expect)
        inst = hashers.MD5Hasher(iv)
        assert inst.iv_size == 16
        assert inst.digest_size == 16
        with pytest.raises(hashers.InvalidHash):
            inst.validate(b'asdf', expect)

    def test_sha1_96(self):
        expect = b'\x72\xD2\x24\xD3\x42\x63\x87\x22\x96\x5F\xA0\xDF'
        iv = b'\x00'*20
        self._check_data(hashers.SHA1_96Hasher, iv, b'test', expect)
        inst = hashers.SHA1_96Hasher(iv)
        assert inst.iv_size == 20
        assert inst.digest_size == 12
        with pytest.raises(hashers.InvalidHash):
            inst.validate(b'asdf', expect)

    def test_md5_96(self):
        expect = b'\xE2\x83\x4E\x84\xB6\xAD\x91\x74\x5B\x22\xFC\xB3'
        iv = b'\x00'*16
        self._check_data(hashers.MD5_96Hasher, iv, b'test', expect)
        inst = hashers.MD5_96Hasher(iv)
        assert inst.iv_size == 16
        assert inst.digest_size == 12
        with pytest.raises(hashers.InvalidHash):
            inst.validate(b'asdf', expect)

    def test_sha256(self):
        expect = (b'\x43\xB0\xCE\xF9\x92\x65\xF9\xE3\x4C\x10\xEA\x9D\x35\x01'
                  b'\x92\x6D\x27\xB3\x9F\x57\xC6\xD6\x74\x56\x1D\x8B\xA2\x36'
                  b'\xE7\xA8\x19\xFB')
        iv = b'\x00'*32
        self._check_data(hashers.SHA256Hasher, iv, b'test', expect)
        inst = hashers.SHA256Hasher(iv)
        assert inst.iv_size == 32
        assert inst.digest_size == 32
        with pytest.raises(hashers.InvalidHash):
            inst.validate(b'asdf', expect)

    def test_sha512(self):
        expect = (b'\x29\xC5\xFA\xB0\x77\xC0\x09\xB9\xE6\x67\x6B\x2F\x08\x2A'
                  b'\x7A\xB3\xB0\x46\x2B\x41\xAC\xF7\x5F\x07\x5B\x5A\x7B\xAC'
                  b'\x56\x19\xEC\x81\xC9\xD8\xBB\x2E\x25\xB6\xD3\x38\x00\xFB'
                  b'\xA2\x79\xEE\x49\x2A\xC7\xD0\x52\x20\xE8\x29\x46\x4D\xF3'
                  b'\xCA\x8E\x00\x29\x8C\x51\x77\x64')
        iv = b'\x00'*64
        self._check_data(hashers.SHA512Hasher, iv, b'test', expect)
        inst = hashers.SHA512Hasher(iv)
        assert inst.iv_size == 64
        assert inst.digest_size == 64
        with pytest.raises(hashers.InvalidHash):
            inst.validate(b'asdf', expect)

    def test_none(self):
        expect = b''
        iv = None
        self._check_data(hashers.NoneHasher, iv, b'test', expect)
        inst = hashers.NoneHasher()
        assert inst.iv_size == 0
        assert inst.digest_size == 0

class TestGetHasher(unittest.TestCase):
    def test_regular(self):
        got = hashers.get_hasher(b'hmac-md5')
        assert got is hashers.MD5Hasher

    def test_missing(self):
        with pytest.raises(ValueError):
            hashers.get_hasher(b'not-an-algorithm')
