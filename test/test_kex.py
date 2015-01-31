from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

import io
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, SHA1


from pyssh import kex
from pyssh import transport
from pyssh.base_types import MPInt, String
from pyssh.crypto.symmetric import BaseCipher
from pyssh.crypto.hashers import BaseHasher
from pyssh.compression import BaseCompressor
from pyssh import packet
from pyssh.constants import SSH_IDENT_STRING
from pyssh.message.tpt import KexDHReply, KexDHInit




class KexTest(object):
    def test_init(self):
        inst = self.create()
        assert inst.session_id == b'\x00'*32
        assert inst.K == self.K

    def test_get_builder(self):
        inst = self.create()
        builder = inst.get_builder()
        assert isinstance(builder, packet.PacketBuilder)
        assert isinstance(builder.encryptor, BaseCipher)
        assert isinstance(builder.hasher, BaseHasher)
        assert isinstance(builder.compressor, BaseCompressor)

    def test_get_reader(self):
        inst = self.create()
        handler = inst.get_reader()

        assert isinstance(handler, packet.PacketReader)
        assert isinstance(handler.decryptor, BaseCipher)
        assert isinstance(handler.validator, BaseHasher)
        assert isinstance(handler.decompressor, BaseCompressor)


class TestClientKex(unittest.TestCase, KexTest):
    def create(self):
        self.K = MPInt(0xFFFFFFFF)
        negotiated = transport.Negotiated(
            b'diffie-hellman-group1-sha1',
            b'ssh-dss',
            b'aes256-cbc',
            b'aes128-cbc',
            b'hmac-md5',
            b'hmac-md5',
            b'none',
            b'none'
            )
        inst = kex.ClientKexState(SHA1(), self.K, b'\x00'*32, negotiated)
        return inst


class TestServerKex(unittest.TestCase, KexTest):
    def create(self):
        self.K = MPInt(0xFFFFFFFF)
        negotiated = transport.Negotiated(
            b'diffie-hellman-group1-sha1',
            b'ssh-dss',
            b'aes256-cbc',
            b'aes128-cbc',
            b'hmac-md5',
            b'hmac-md5',
            b'none',
            b'none'
            )
        inst = kex.ServerKexState(SHA1(), self.K, b'\x00'*32, negotiated)
        return inst


class ExchangeTest(object):
    def create(self):
        return self.cls(self.negotiated, self.prefix)


    def test_init(self):
        inst = self.create()

    # test some internal-only code for sanity
    def test_kexdh_init_values(self):
        g, p = self.cls.G, self.cls.P
        inst = self.create()
        e, x = inst._make_kexdh_init_values()
        assert e == pow(g, x, p)

    def test_calculate_hexdh_hash(self):
        inst = self.create()
        got = inst._calculate_kexdh_hash(self.host_key, self.e, self.f, self.K)
        assert got.value == self.hashval

    def test_kexdh_reply_hash(self):
        g, p = self.cls.G, self.cls.P
        inst = self.create()
        mock_init = mock.MagicMock()
        mock_init.e = self.e
        y, f, K = inst._make_kexdh_reply_values(mock_init)
        assert f.value == pow(g, y, p)
        assert K.value == pow(self.e.value, y, p)

    @mock.patch('pyssh.kex.get_asymmetric_algorithm')
    def test_wait_exchange(self, get_algorithm):
        tport = mock.MagicMock()
        dh_init = tport.read_msg.return_value
        dh_init.e = self.e
        algorithm = get_algorithm.return_value
        algorithm.pack_pubkey.return_value = b'\x00'
        algorithm.sign.return_value = b'\x00'

        inst = self.create()
        with mock.patch.object(inst, '_make_kexdh_reply_values') as patch:
            with mock.patch.object(inst, '_calculate_kexdh_hash') as kexdh:
                patch.return_value = 0, self.f, self.K
                inst.wait_exchange(tport)

        expect = self.cls.REPLY_CLS(String(b'\x00'), self.f, String(b'\x00'))
        tport.assert_has_calls([
            mock.call.read_msg(types=[KexDHInit]),
            mock.call.send_msg(expect)
        ])

    @mock.patch('pyssh.kex.get_asymmetric_algorithm')
    def test_start_exchange(self, get_algorithm):
        tport = mock.MagicMock()
        dh_reply = tport.read_msg.return_value
        dh_reply.f = self.f
        dh_reply.k_s = self.host_key
        
        inst = self.create()
        with mock.patch.object(inst, '_make_kexdh_init_values') as patch:
            patch.return_value = self.e.value, 0
            inst.start_exchange(tport)

        expect = self.cls.INIT_CLS(self.e)
        tport.assert_has_calls([
            mock.call.send_msg(expect),
            mock.call.read_msg(types=[KexDHReply])
        ])


class TestDHGroup14(unittest.TestCase, ExchangeTest):
    def setUp(self):
        self.cls = kex.DiffieHellmanGroup14Sha1
        self.negotiated = transport.Negotiated(
            b'diffie-hellman-group1-sha1',
            b'ssh-dss',
            b'aes256-cbc',
            b'aes128-cbc',
            b'hmac-md5',
            b'hmac-md5',
            b'none',
            b'none'
        )
        self.host_key = String(b'\x00\x00')
        self.prefix = b'\x00'*50
        self.e = MPInt(3)
        self.f = MPInt(2)
        self.f = MPInt(10)
        self.K = MPInt(9)
        self.hashval = b'\x9B\xAC\x7F\x8B\x2E\x8B\x59\x96\xE0\x7A\xE8\x34\x14\x32\x10\x59\x88\x0D\x8E\x5D'


class TestGetKex(unittest.TestCase):
    def test_exists(self):
        assert kex.get_kex_handler(b'diffie-hellman-group1-sha1') is \
               kex.DiffieHellmanGroup1Sha1

    def test_not_exists(self):
        with pytest.raises(kex.InvalidKexMethod):
            kex.get_kex_handler(b'no-such-method')