"""Test for Auth messages.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from pyssh.message import auth

from pyssh.message.base import unpack_from, Message, State
from pyssh.base_types import String, Byte, NameList, Boolean
from pyssh.constants import (SSH_MSG_USERAUTH_REQUEST, SSH_METHOD_PUBLICKEY,
                             RANGE_USERAUTH_SPECIFIC, SSH_METHOD_PASSWORD,
                             SSH_METHOD_NONE, SSH_MSG_USERAUTH_FAILURE,
                             SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_BANNER)

import pytest
import unittest
from io import BytesIO

class BaseAuth(object):
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


class TestAuthRequest(unittest.TestCase, BaseAuth):
    def setUp(self):
        self.header = Byte(SSH_MSG_USERAUTH_REQUEST)
        self.username = String(b'some_user')
        self.svcname = String(b'some_service')
        self.methodname = String(b'demo-method')

        self.cls = auth.AuthRequest
        self.args = (self.username, self.svcname, self.methodname)
        self.packed = (
            b'\x32'
            b'\x00\x00\x00\x09some_user'
            b'\x00\x00\x00\x0Csome_service'
            b'\x00\x00\x00\x0Bdemo-method'
        )
        self.state = State()

    def tearDown(self):
        self.cls._registered.pop(self.methodname, None)

    def test_unpack(self):
        @auth.AuthRequest.register(self.methodname)
        class DemoRequest(auth.AuthRequest):
            SPEC = []
            def __init__(self, username, svcname):
                super(DemoRequest, self).__init__(username, svcname, self.METHODNAME)

        inst = unpack_from(BytesIO(self.packed), self.state)
        assert isinstance(inst, DemoRequest)


class TestAuthFailure(unittest.TestCase, BaseAuth):
    def setUp(self):
        self.header = Byte(SSH_MSG_USERAUTH_FAILURE)
        self.auth_continue = NameList(['foo-auth', 'bar-auth'])
        self.partial = Boolean(False)

        self.cls = auth.AuthFailure
        self.args = (self.auth_continue, self.partial)
        self.packed = (
            b'\x33'
            b'\x00\x00\x00\x11foo-auth,bar-auth'
            b'\x00'
        )
        self.state = State()


class TestAuthSuccess(unittest.TestCase, BaseAuth):
    def setUp(self):
        self.header = Byte(SSH_MSG_USERAUTH_SUCCESS)

        self.cls = auth.AuthSuccess
        self.args = ()
        self.packed = b'\x34'
        self.state = State()


class TestAuthBanner(unittest.TestCase, BaseAuth):
    def setUp(self):
        self.header = Byte(SSH_MSG_USERAUTH_BANNER)
        self.message = String(b'welcome to my computer')
        self.language = String(b'en-us')

        self.cls = auth.AuthBanner
        self.args = (self.message, self.language)
        self.packed = (
            b'\x35'
            b'\x00\x00\x00\x16welcome to my computer'
            b'\x00\x00\x00\x05en-us'
        )
        self.state = State()


class TestPublicKeyUnsigned(unittest.TestCase, BaseAuth):
    def setUp(self):
        self.header = Byte(SSH_MSG_USERAUTH_REQUEST)
        self.methodname = String(b'publickey')
        self.username = String(b'some_user')
        self.svcname = String(b'some_service')
        self.algname = String(b'some_algorithm')
        self.signed = Boolean(False)
        self.blob = String(b'some_blob')

        self.cls = auth.PublicKeyAuth
        self.args = (self.username, self.svcname, self.signed, self.algname,
                     self.blob)
        self.packed = (
            b'\x32'
            b'\x00\x00\x00\x09some_user'
            b'\x00\x00\x00\x0Csome_service'
            b'\x00\x00\x00\x09publickey'
            b'\x00'
            b'\x00\x00\x00\x0Esome_algorithm'
            b'\x00\x00\x00\x09some_blob'
        )
        self.state = State()

    def test_init(self):
        inst = super(TestPublicKeyUnsigned, self).test_init()
        assert inst.METHODNAME == self.methodname
        return inst

class TestPublicKeySigned(unittest.TestCase, BaseAuth):
    def setUp(self):
        self.header = Byte(SSH_MSG_USERAUTH_REQUEST)
        self.methodname = String(b'publickey')
        self.username = String(b'some_user')
        self.svcname = String(b'some_service')
        self.algname = String(b'some_algorithm')
        self.signed = Boolean(True)
        self.blob = String(b'some_blob')
        self.signature = String(b'some_signature')

        self.cls = auth.PublicKeyAuth
        self.args = (self.username, self.svcname, self.signed, self.algname,
                     self.blob, self.signature)
        self.packed = (
            b'\x32'
            b'\x00\x00\x00\x09some_user'
            b'\x00\x00\x00\x0Csome_service'
            b'\x00\x00\x00\x09publickey'
            b'\x01'
            b'\x00\x00\x00\x0Esome_algorithm'
            b'\x00\x00\x00\x09some_blob'
            b'\x00\x00\x00\x0Esome_signature'
        )
        self.state = State()

    def test_init(self):
        inst = super(TestPublicKeySigned, self).test_init()
        assert inst.METHODNAME == self.methodname
        return inst

    def test_from_pkey(self):
        signature = self.signature.value
        class PKey(object):
            def sign(self, data):
                return signature

        pkey = PKey()
        inst = auth.PublicKeyAuth.from_pkey(self.username, self.svcname,
                                            self.algname, self.blob, pkey)
        assert inst.pack() == self.packed
        assert inst.HEADER == self.header
        assert inst.METHODNAME == self.methodname


class TestPKAuthSuccess(unittest.TestCase, BaseAuth):
    def setUp(self):
        self.header = Byte(RANGE_USERAUTH_SPECIFIC[0])
        self.algname = String(b'some_algorithm')
        self.blob = String(b'some_blob')

        self.cls = auth.PKAuthSuccess
        self.args = (self.algname, self.blob)
        self.packed = (
            b'\x3C'
            b'\x00\x00\x00\x0Esome_algorithm'
            b'\x00\x00\x00\x09some_blob'
        )
        self.state = State(auth_method=b'publickey')


class TestPasswordAuth(unittest.TestCase, BaseAuth):
    def setUp(self):
        self.header = Byte(SSH_MSG_USERAUTH_REQUEST)
        self.methodname = String(b'password')
        self.username = String(b'some_user')
        self.svcname = String(b'some_service')
        self.password = String(b'some_password')

        self.cls = auth.PasswordAuth
        self.args = (self.username, self.svcname, self.password)
        self.packed = (
            b'\x32'
            b'\x00\x00\x00\x09some_user'
            b'\x00\x00\x00\x0Csome_service'
            b'\x00\x00\x00\x08password'
            b'\x00\x00\x00\x0Dsome_password'
        )
        self.state = State()

    def test_init(self):
        inst = super(TestPasswordAuth, self).test_init()
        assert inst.METHODNAME == self.methodname
        return inst


class TestNoneAuth(unittest.TestCase, BaseAuth):
    def setUp(self):
        self.header = Byte(SSH_MSG_USERAUTH_REQUEST)
        self.methodname = String(b'none')
        self.username = String(b'some_user')
        self.svcname = String(b'some_service')

        self.cls = auth.NoneAuth
        self.args = (self.username, self.svcname)
        self.packed = (
            b'\x32'
            b'\x00\x00\x00\x09some_user'
            b'\x00\x00\x00\x0Csome_service'
            b'\x00\x00\x00\x04none'
        )
        self.state = State()
