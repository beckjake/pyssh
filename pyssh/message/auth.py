"""All the messages defined in RFC 4252: SSH Authentication Protocol
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from pyssh.base_types import Byte, Boolean, String, NameList
from pyssh.constants import (SSH_MSG_USERAUTH_REQUEST, SSH_METHOD_PUBLICKEY,
                             RANGE_USERAUTH_SPECIFIC, SSH_METHOD_PASSWORD,
                             SSH_METHOD_NONE, SSH_MSG_USERAUTH_FAILURE,
                             SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_BANNER)
from .base import Message

#pylint: disable=R0903,R0913

@Message.register(Byte(SSH_MSG_USERAUTH_REQUEST))
class AuthRequest(Message):
    """Auth Request: Section 5."""
    METHODNAME = None
    SPEC = [('username', String), ('svcname', String), ('methodname', String)]
    def __init__(self, username, svcname, methodname):
        super(AuthRequest, self).__init__(self.HEADER)
        self.username = username
        self.svcname = svcname
        self.methodname = methodname

    @classmethod
    def register(cls, methodname):
        """Decorator to register a class as the class for methodname."""
        return cls._generic_register('METHODNAME', methodname)


@Message.register(Byte(SSH_MSG_USERAUTH_FAILURE))
class AuthFailure(Message):
    """AuthFailure: Section 5.1"""
    SPEC = [('auth_continue', NameList), ('partial', Boolean)]
    def __init__(self, auth_continue, partial):
        super(AuthFailure, self).__init__(self.HEADER)
        self.auth_continue = auth_continue
        self.partial = partial


@Message.register(Byte(SSH_MSG_USERAUTH_SUCCESS))
class AuthSuccess(Message):
    """AuthSuccess: Section 5.1"""
    SPEC = []
    def __init__(self):
        super(AuthSuccess, self).__init__(self.HEADER)


@Message.register(Byte(SSH_MSG_USERAUTH_BANNER))
class AuthBanner(Message):
    """AuthBanner: Section 5.4"""
    SPEC = [('message', String), ('language', String)]
    def __init__(self, message, language):
        super(AuthBanner, self).__init__(self.HEADER)
        self.message = message
        self.language = language


# Public key auth: RFC 4252, section 7
@AuthRequest.register(String(SSH_METHOD_PUBLICKEY))
class PublicKeyAuth(AuthRequest):
    """Public Key Auth: Section 7"""
    SPEC = [('signed', Boolean), ('algname', String), ('blob', String),
            ('signature', String)]
    def __init__(self, username, svcname, signed, algname, blob, signature=None):
        super(PublicKeyAuth, self).__init__(username, svcname, self.METHODNAME)
        self.signed = signed
        self.algname = algname
        self.blob = blob
        self.signature = signature

    @classmethod
    def from_pkey(cls, username, svcname, algname, blob, pkey):
        """Instantiate using a pkey to make the signature."""
        obj = cls(username, svcname, Boolean(True), algname, blob)
        obj.signature = String(pkey.sign(obj.pack()))
        return obj

    @classmethod
    def unpack_from(cls, stream, state, kwargs):
        # this requires special handling, and it's a mess =\
        for field_name, field_type in cls.SPEC:
            if field_name == 'signature':
                if not kwargs['signed'].value:
                    break
            kwargs[field_name] = field_type.unpack_from(stream)
        assert not cls._key
        return cls(**kwargs)

@Message.register_conditional(Byte(RANGE_USERAUTH_SPECIFIC[0]))
class PKAuthSuccess(Message):
    """Public Key Auth Success: Section 7"""
    SPEC = [('algname', String), ('blob', String)]
    SATISFIERS = {'auth_method': SSH_METHOD_PUBLICKEY}
    def __init__(self, algname, blob):
        super(PKAuthSuccess, self).__init__(self.HEADER)
        self.algname = algname
        self.blob = blob

@AuthRequest.register(String(SSH_METHOD_PASSWORD))
class PasswordAuth(AuthRequest):
    """Password Auth: Section 8"""
    SPEC = [('password', String)]
    def __init__(self, username, svcname, password):
        super(PasswordAuth, self).__init__(username, svcname, self.METHODNAME)
        self.password = password


# TODO: SSH_MSG_USERAUTH_PASSWD_CHANGEREQ + responses

# TODO: Hostbased auth: RFC 4252, section 9

@AuthRequest.register(String(SSH_METHOD_NONE))
class NoneAuth(AuthRequest):
    """None auth: Section 10"""
    SPEC = []
    def __init__(self, username, svcname):
        super(NoneAuth, self).__init__(username, svcname, self.METHODNAME)




