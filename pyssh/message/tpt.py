"""All the messages with a header between 0-49.

Mostly from RFC 4253: SSH Transport Layer Protocol
"""

from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals


import os

from pyssh.base_types import (Byte, Boolean, String, UInt32, NameList, MPInt,
                              RawByte16)
from pyssh.constants import (SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS,
                             SSH_MSG_KEXDH_INIT, SSH_MSG_KEXDH_REPLY,
                             KEX_DH_GROUP1_SHA1, KEX_DH_GROUP14_SHA1,
                             SSH_MSG_SERVICE_REQUEST, SSH_MSG_SERVICE_ACCEPT,
                             SSH_MSG_DISCONNECT, SSH_MSG_IGNORE, SSH_MSG_DEBUG,
                             SSH_MSG_UNIMPLEMENTED)
from .base import Message

#pylint: disable=R0903,R0913,C0103,R0902
@Message.register(Byte(SSH_MSG_KEXINIT))
class KexInit(Message):
    """KexInit: Section 7.1"""
    SPEC = [
        ('random_data', RawByte16),
        ('kex_methods', NameList),
        ('server_host_key_algorithms', NameList),
        ('ciphers_client_to_server', NameList),
        ('ciphers_server_to_client', NameList),
        ('hashes_client_to_server', NameList),
        ('hashes_server_to_client', NameList),
        ('comp_client_to_server', NameList),
        ('comp_server_to_client', NameList),
        ('languages_client_to_server', NameList),
        ('languages_server_to_client', NameList),
        ('first_kex_message_follows', Boolean),
        ('reserved', UInt32)
    ]
    def __init__(self, kex_methods, server_host_key_algorithms,
                 ciphers_client_to_server, ciphers_server_to_client,
                 hashes_client_to_server, hashes_server_to_client,
                 comp_client_to_server, comp_server_to_client,
                 languages_client_to_server, languages_server_to_client,
                 first_kex_message_follows, random_data=None, reserved=None):
        super(KexInit, self).__init__(self.HEADER)
        self.kex_methods = kex_methods
        self.server_host_key_algorithms = server_host_key_algorithms
        self.ciphers_client_to_server = ciphers_client_to_server
        self.ciphers_server_to_client = ciphers_server_to_client
        self.hashes_client_to_server = hashes_client_to_server
        self.hashes_server_to_client = hashes_server_to_client
        self.comp_client_to_server = comp_client_to_server
        self.comp_server_to_client = comp_server_to_client
        self.languages_client_to_server = languages_client_to_server
        self.languages_server_to_client = languages_server_to_client
        self.first_kex_message_follows = first_kex_message_follows
        self.random_data = os.urandom(16) if random_data is None else random_data
        print(random_data)
        print(self.random_data)
        self.reserved = UInt32(0) if reserved is None else reserved

    def update(self, **kwargs):
        """Update values in the KexInit."""
        for key, value in kwargs.items():
            assert hasattr(self, key)
            setattr(self, key, value)


@Message.register(Byte(SSH_MSG_NEWKEYS))
class KexNewkeys(Message):
    """New Keys: Section 7.3"""
    SPEC = []
    def __init__(self):
        super(KexNewkeys, self).__init__(self.HEADER)


class KexDHInit(Message):
    """Kex DH Init: Section 8"""
    SPEC = [('e', MPInt)]
    def __init__(self, e):
        super(KexDHInit, self).__init__(self.HEADER)
        self.e = MPInt(e)


@Message.register_conditional(Byte(SSH_MSG_KEXDH_INIT))
class KexDHGroup1Init(KexDHInit):
    """Kex DH Init: Section 8"""
    SATISFIERS = {'kex_method': KEX_DH_GROUP1_SHA1}



@Message.register_conditional(Byte(SSH_MSG_KEXDH_INIT))
class KexDHGroup14Init(KexDHInit):
    """Kex DH Init: Section 8"""
    SATISFIERS = {'kex_method': KEX_DH_GROUP14_SHA1}


class KexDHReply(Message):
    """Kex DH Reply: Section 8"""
    HEADER = Byte(SSH_MSG_KEXDH_REPLY)
    SPEC = [('k_s', String), ('f', MPInt), ('h_sig', String)]
    def __init__(self, k_s, f, h_sig):
        super(KexDHReply, self).__init__(self.HEADER)
        self.k_s = k_s
        self.f = f
        self.h_sig = h_sig


@Message.register_conditional(Byte(SSH_MSG_KEXDH_REPLY))
class KexDHGroup1Reply(KexDHReply):
    """Kex DH Reply: Section 8"""
    SATISFIERS = {'kex_method': KEX_DH_GROUP1_SHA1}


@Message.register_conditional(Byte(SSH_MSG_KEXDH_REPLY))
class KexDHGroup14Reply(KexDHReply):
    """Kex DH Reply: Section 8"""
    SATISFIERS = {'kex_method': KEX_DH_GROUP14_SHA1}


@Message.register(Byte(SSH_MSG_SERVICE_REQUEST))
class ServiceRequest(Message):
    """Service Request: Section 10."""
    SPEC = [('name', String)]
    def __init__(self, name):
        super(ServiceRequest, self).__init__(self.HEADER)
        self.name = name


@Message.register(Byte(SSH_MSG_SERVICE_ACCEPT))
class ServiceAccept(Message):
    """Service Accept: Section 10."""
    SPEC = [('name', String)]
    def __init__(self, name):
        super(ServiceAccept, self).__init__(self.HEADER)
        self.name = name


@Message.register(Byte(SSH_MSG_DISCONNECT))
class Disconnect(Message):
    """Disconnect: Section 11.1"""
    SPEC = [('reason_code', UInt32), ('description', String),
            ('language_tag', String)]
    def __init__(self, reason_code, description, language_tag):
        super(Disconnect, self).__init__(self.HEADER)
        self.reason_code = reason_code
        self.description = description
        self.language_tag = language_tag


@Message.register(Byte(SSH_MSG_IGNORE))
class Ignore(Message):
    """Ignore: Section 11.2"""
    SPEC = [('data', String)]
    def __init__(self, data):
        super(Ignore, self).__init__(self.HEADER)
        self.data = data


@Message.register(Byte(SSH_MSG_DEBUG))
class Debug(Message):
    """Debug: Section 11.3"""
    SPEC = [('always_display', Boolean), ('message', String),
            ('language_tag', String)]

    def __init__(self, always_display, message, language_tag):
        super(Debug, self).__init__(self.HEADER)
        self.always_display = always_display
        self.message = message
        self.language_tag = language_tag


@Message.register(Byte(SSH_MSG_UNIMPLEMENTED))
class Unimplemented(Message):
    """Unimplemented: Section 11.4
    """
    SPEC = [('sequence_number', UInt32)]
    def __init__(self, sequence_number):
        super(Unimplemented, self).__init__(self.HEADER)
        self.sequence_number = sequence_number

