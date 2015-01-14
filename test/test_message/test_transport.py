"""Tests for Transport messages.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from pyssh.message import transport
from pyssh.message.base import unpack_from, Message, State
from pyssh.base_types import (Byte, Boolean, String, UInt32, NameList, MPInt,
                              RawByte16)

from pyssh.constants import (SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS,
                             SSH_MSG_KEXDH_INIT, SSH_MSG_KEXDH_REPLY,
                             KEX_DH_GROUP1_SHA1, KEX_DH_GROUP14_SHA1,
                             SSH_MSG_SERVICE_REQUEST, SSH_MSG_SERVICE_ACCEPT,
                             SSH_MSG_DISCONNECT, SSH_MSG_IGNORE, SSH_MSG_DEBUG,
                             SSH_MSG_UNIMPLEMENTED)

import pytest

import os
import unittest
from io import BytesIO


class BaseTransport(object):
    def test_init(self):
        inst = self.cls(*self.args)
        assert inst.HEADER == self.header
        return inst

    def test_pack(self):
        inst = self.cls(*self.args)
        assert inst.pack() == self.packed
        return inst

    def test_unpack(self):
        stream = BytesIO(self.packed)
        inst = unpack_from(stream, state=self.state)
        assert isinstance(inst, self.cls)
        assert not stream.read()
        return inst

class TestKexInit(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_KEXINIT)
        self.kex_methods = NameList(['some-method', 'some-other-method'])
        self.server_host_key_algorithms = NameList(['some-algorithm',
                                                    'some-other-algorithm'])
        self.ciphers_client_to_server = NameList(['some-cipher',
                                                  'some-other-cipher'])
        self.ciphers_server_to_client = NameList(['some-cipher-2',
                                                  'some-other-cipher-2'])
        self.hashes_client_to_server = NameList(['some-hash',
                                                 'some-other-hash'])
        self.hashes_server_to_client = NameList(['some-hash-2',
                                                 'some-other-hash-2'])
        self.comp_client_to_server = NameList(['some-comp',
                                               'some-other-comp'])
        self.comp_server_to_client = NameList(['some-comp-2',
                                               'some-other-comp-2'])
        self.languages_client_to_server = NameList(['some-language',
                                                    'some-other-language'])
        self.languages_server_to_client = NameList(['some-language-2',
                                                    'some-other-language-2'])
        self.first_kex_message_follows = Boolean(False)
        data = os.urandom(16)
        print(data)
        self.random_data = RawByte16(data)
        print(self.random_data.value)
        print(self.random_data.pack())

        self.cls = transport.KexInit
        self.args = (
            self.kex_methods,
            self.server_host_key_algorithms,
            self.ciphers_client_to_server,
            self.ciphers_server_to_client,
            self.hashes_client_to_server,
            self.hashes_server_to_client,
            self.comp_client_to_server,
            self.comp_server_to_client,
            self.languages_client_to_server,
            self.languages_server_to_client,
            self.first_kex_message_follows,
            self.random_data,
            UInt32(0)
        )
        self.packed = b'\x14' + data + (
            b'\x00\x00\x00\x1Dsome-method,some-other-method'
            b'\x00\x00\x00\x23some-algorithm,some-other-algorithm'
            b'\x00\x00\x00\x1Dsome-cipher,some-other-cipher'
            b'\x00\x00\x00\x21some-cipher-2,some-other-cipher-2'
            b'\x00\x00\x00\x19some-hash,some-other-hash'
            b'\x00\x00\x00\x1Dsome-hash-2,some-other-hash-2'
            b'\x00\x00\x00\x19some-comp,some-other-comp'
            b'\x00\x00\x00\x1Dsome-comp-2,some-other-comp-2'
            b'\x00\x00\x00\x21some-language,some-other-language'
            b'\x00\x00\x00\x25some-language-2,some-other-language-2'
            b'\x00'
            b'\x00\x00\x00\x00'
        )
        self.state = State()
        print(self.cls(*self.args).pack()[1:17  ])

    def test_init(self):
        inst = super(TestKexInit, self).test_init()
        assert inst.kex_methods == self.kex_methods
        assert inst.server_host_key_algorithms == self.server_host_key_algorithms
        assert inst.ciphers_client_to_server == self.ciphers_client_to_server
        assert inst.ciphers_server_to_client == self.ciphers_server_to_client

        assert inst.random_data == self.random_data


class TestKexNewKeys(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_NEWKEYS)

        self.args = ()
        self.cls = transport.KexNewkeys
        self.packed = b'\x15'
        self.state = State()

class TestKexDHGroup1Init(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_KEXDH_INIT)
        self.e = MPInt(0x9A378F9B2E332A7)

        self.args = (self.e,)
        self.cls = transport.KexDHGroup1Init
        self.packed = b'\x1E\x00\x00\x00\x08\x09\xA3\x78\xF9\xB2\xE3\x32\xA7'
        self.state = State(kex_method=KEX_DH_GROUP1_SHA1)


class TestKexDHGroup14Init(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_KEXDH_INIT)
        self.e = MPInt(0x9A378F9B2E332A7)

        self.args = (self.e,)
        self.cls = transport.KexDHGroup14Init
        self.packed = b'\x1E\x00\x00\x00\x08\x09\xA3\x78\xF9\xB2\xE3\x32\xA7'
        self.state = State(kex_method=KEX_DH_GROUP14_SHA1)


class TestKexDHGroup1Reply(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_KEXDH_REPLY)
        self.k_s = String(b'some_k_s')
        self.f = MPInt(0x9A378F9B2E332A7)
        self.h_sig = String(b'some_h_sig')

        self.args = (self.k_s, self.f, self.h_sig)
        self.cls = transport.KexDHGroup1Reply
        self.packed = (
            b'\x1F'
            b'\x00\x00\x00\x08some_k_s'
            b'\x00\x00\x00\x08\x09\xA3\x78\xF9\xB2\xE3\x32\xA7'
            b'\x00\x00\x00\x0Asome_h_sig'
        )
        self.state = State(kex_method=KEX_DH_GROUP1_SHA1)


class TestKexDHGroup14Reply(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_KEXDH_REPLY)
        self.k_s = String(b'some_k_s')
        self.f = MPInt(0x9A378F9B2E332A7)
        self.h_sig = String(b'some_h_sig')

        self.args = (self.k_s, self.f, self.h_sig)
        self.cls = transport.KexDHGroup14Reply
        self.packed = (
            b'\x1F'
            b'\x00\x00\x00\x08some_k_s'
            b'\x00\x00\x00\x08\x09\xA3\x78\xF9\xB2\xE3\x32\xA7'
            b'\x00\x00\x00\x0Asome_h_sig'
        )
        self.state = State(kex_method=KEX_DH_GROUP14_SHA1)


class TestServiceRequest(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_SERVICE_REQUEST)
        self.name = String(b'some-service')

        self.args = (self.name,)
        self.cls = transport.ServiceRequest
        self.packed = (
            b'\x05'
            b'\x00\x00\x00\x0Csome-service'
        )
        self.state = State()


class TestServiceAccept(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_SERVICE_ACCEPT)
        self.name = String(b'some-service')

        self.args = (self.name,)
        self.cls = transport.ServiceAccept
        self.packed = (
            b'\x06'
            b'\x00\x00\x00\x0Csome-service'
        )
        self.state = State()


class TestDisconnect(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_DISCONNECT)
        self.reason_code = UInt32(0xFFFFFFFF)
        self.description = String(b'some-description')
        self.language_tag = String(b'en-us')

        self.args = (self.reason_code, self.description, self.language_tag)
        self.cls = transport.Disconnect
        self.packed = (
            b'\x01'
            b'\xFF\xFF\xFF\xFF'
            b'\x00\x00\x00\x10some-description'
            b'\x00\x00\x00\x05en-us'
        )
        self.state = State()


class TestIgnore(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_IGNORE)
        self.data = String(b'ignore-me')

        self.args = (self.data,)
        self.cls = transport.Ignore
        self.packed = (
            b'\x02'
            b'\x00\x00\x00\x09ignore-me'
        )
        self.state = State()


class TestDebug(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_DEBUG)
        self.always_display = Boolean(False)
        self.message = String(b'some_message')
        self.language_tag = String(b'en-us')

        self.args = (self.always_display, self.message, self.language_tag)
        self.cls = transport.Debug
        self.packed = (
            b'\x04'
            b'\x00'
            b'\x00\x00\x00\x0Csome_message'
            b'\x00\x00\x00\x05en-us'
        )
        self.state = State()


class TestUnimplemented(unittest.TestCase, BaseTransport):
    def setUp(self):
        self.header = Byte(SSH_MSG_UNIMPLEMENTED)
        self.sequence_number = UInt32(0xAB)


        self.args = (self.sequence_number,)
        self.cls = transport.Unimplemented
        self.packed = (
            b'\x03'
            b'\x00\x00\x00\xAB'
        )
        self.state = State()


