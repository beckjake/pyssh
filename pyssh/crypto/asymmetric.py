"""Implement asymmetric cryptography.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.dsa import (DSAPublicNumbers,
                                                           DSAParameterNumbers)
from cryptography.hazmat.primitives.asymmetric.utils import encode_rfc6979_signature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.backends import default_backend

from collections import OrderedDict
import io

from pyssh.constants import ENC_SSH_RSA, ENC_SSH_DSS
from pyssh.base_types import Packable, String, MPInt


class UnsupportedKeyProtocol(Exception):
    """Key protocol not supported."""


class InvalidAlgorithm(Exception):
    """Mismatched algorithm"""


#TODO: ECDSA (RFC 5656)
class BasePublicKey(Packable):
    SIGNATURE = None
    FORMAT_STR = None
    def get_public_key(self):
        """Get the public key object."""
        raise NotImplementedError('subclasses must implement')

    def verify(self, signature, data):
        """Verify the signature against the given data."""
        raise NotImplementedError('subclasses must implement')

    @classmethod
    def unpack_from(cls, stream):
        keytype = String.unpack_from(stream)
        if cls.FORMAT_STR != keytype:
            msg = 'Got {!r}, expected {!r}'.format(keytype, cls.FORMAT_STR)
            raise InvalidAlgorithm(msg)

    def verify_from_blob(self, signature_blob, data):
        signature = self.SIGNATURE.unpack_from(io.BytesIO(signature_blob))
        self.verify(signature, data)

class BaseSignature(Packable):
    @classmethod
    def unpack_from(cls, stream):
        keytype = String.unpack_from(stream)
        if cls.FORMAT_STR != keytype:
            msg = 'Got {!r}, expected {!r}'.format(keytype, cls.FORMAT_STR)
            raise InvalidAlgorithm(msg)


class RSASignature(BaseSignature):
    FORMAT_STR = String(ENC_SSH_RSA)
    def __init__(self, blob):
        assert isinstance(blob, bytes)
        self.blob = blob

    def pack(self):
        """
        The value for 'rsa_signature_blob' is encoded as a string containing
        s (which is an integer, without lengths or padding, unsigned, and in
        network byte order).
        """
        blob = String(self.blob)
        return b''.join((self.FORMAT_STR.pack(), blob.pack()))

    @classmethod
    def unpack_from(cls, stream):
        super(RSASignature, cls).unpack_from(stream)
        blob = String.unpack_from(stream)
        return cls(blob.value)


class RSAPublicKey(BasePublicKey):
    FORMAT_STR = String(ENC_SSH_RSA)
    SIGNATURE = RSASignature
    def __init__(self, e, n):
        self.e = e
        self.n = n

    def pack(self):
        return b''.join((
            self.FORMAT_STR.pack(),
            self.e.pack(),
            self.n.pack()
        ))

    @classmethod
    def unpack_from(cls, stream):
        super(RSAPublicKey, cls).unpack_from(stream)
        e = MPInt.unpack_from(stream)
        n = MPInt.unpack_from(stream)
        return cls(e, n)

    def get_public_key(self):
        public_numbers = RSAPublicNumbers(self.e.value, self.n.value)
        backend = default_backend()
        return public_numbers.public_key(backend)

    def verify(self, signature, data):
        """Signature should be an RSASignature object."""
        pubkey = self.get_public_key()
        assert isinstance(signature, self.SIGNATURE)
        verifier = pubkey.verifier(
            signature.blob,
            PKCS1v15(),
            hashes.SHA1()
        )
        verifier.update(data)
        verifier.verify()


class DSASignature(BaseSignature):
    """
    The value for 'dss_signature_blob' is encoded as a string containing
    r, followed by s (which are 160-bit integers, without lengths or
    padding, unsigned, and in network byte order).
    """
    FORMAT_STR = String(ENC_SSH_DSS)
    def __init__(self, r, s):
        self.r = int(r)
        self.s = int(s)

    def pack(self):
        blob = String(
            self.r.to_bytes(20, 'big', signed=False) +
            self.s.to_bytes(20, 'big', signed=False))
        return b''.join((self.FORMAT_STR.pack(), blob.pack()))

    @property
    def blob(self):
        return encode_rfc6979_signature(self.r, self.s)

    @classmethod
    def unpack_from(cls, stream):
        """Assume FORMAT_STR has already been read"""
        super(DSASignature, cls).unpack_from(stream)
        blob = String.unpack_from(stream)
        r = int.from_bytes(blob.value[:20], 'big', signed=False)
        s = int.from_bytes(blob.value[20:], 'big', signed=False)
        return cls(r, s)


class DSAPublicKey(BasePublicKey):
    FORMAT_STR = String(ENC_SSH_DSS)
    SIGNATURE = DSASignature
    def __init__(self, p, q, g, y):
        self.p = p
        self.q = q
        self.g = g
        self.y = y

    def pack(self):
        return b''.join((
            self.FORMAT_STR.pack(),
            self.p.pack(),
            self.q.pack(),
            self.g.pack(),
            self.y.pack()
        ))

    @classmethod
    def unpack_from(cls, stream):
        super(DSAPublicKey, cls).unpack_from(stream)
        p = MPInt.unpack_from(stream)
        q = MPInt.unpack_from(stream)
        g = MPInt.unpack_from(stream)
        y = MPInt.unpack_from(stream)
        return cls(p, q, g, y)


    def get_public_key(self):
        parameter_numbers = DSAParameterNumbers(self.p.value, self.q.value,
                                                self.g.value)
        pub = DSAPublicNumbers(self.y.value, parameter_numbers)
        backend = default_backend()
        return pub.public_key(backend)


    def verify(self, signature, data):
        """Signature should be a DSASignature object."""
        pubkey = self.get_public_key()
        assert isinstance(signature, self.SIGNATURE)
        verifier = pubkey.verifier(signature.blob, hashes.SHA1())
        verifier.update(data)
        verifier.verify()


PUBLIC_KEY_PROTOCOLS = OrderedDict((
    (ENC_SSH_RSA, RSAPublicKey),
    (ENC_SSH_DSS, DSAPublicKey)
))


def get_public_key(keytype, host_key, signature_blob=None, data=None):
    """Get the referenced public key type. If a signature_blob blob is included,
    validate it.
    """
    try:
        handler = PUBLIC_KEY_PROTOCOLS[keytype]
    except KeyError:
        raise UnsupportedKeyProtocol(keytype)
    keystream = io.BytesIO(host_key)
    key = handler.unpack_from(keystream)
    if signature_blob:
        key.verify_from_blob(signature_blob, data)
    return key

