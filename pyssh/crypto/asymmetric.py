"""Implement asymmetric cryptography.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, utils, padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.backends import default_backend

from collections import OrderedDict
import io

from builtins import int

from pyssh.constants import ENC_SSH_RSA, ENC_SSH_DSS
from pyssh.base_types import Packable, String, MPInt


class UnsupportedKeyProtocol(Exception):
    """Key protocol not supported."""


class InvalidAlgorithm(Exception):
    """Mismatched algorithm"""


#TODO: ECDSA (RFC 5656)
class BaseAlgorithm(object):
    FORMAT_STR = None
    PUBKEY_CLASS = None
    PRIVKEY_CLASS = None
    def __init__(self, privkey=None, pubkey=None, signature_blob=None):
        self.privkey = privkey
        self.pubkey = pubkey
        self.signature_blob = signature_blob

    def unpack_signature(self, stream):
        self._check_keytype(stream)
        self.signature_blob = String.unpack_from(stream).value

    def pack_signature(self):
        return b''.join([
            self.FORMAT_STR.pack(),
            String(self.signature_blob).pack()
        ])

    def unpack_pubkey(self, stream):
        raise NotImplementedError('not implemented')

    def pack_pubkey(self):
        raise NotImplementedError('not implemented')

    @classmethod
    def _check_keytype(cls, stream):
        keytype = String.unpack_from(stream)
        if cls.FORMAT_STR != keytype:
            msg = 'Got {!r}, expected {!r}'.format(keytype, cls.FORMAT_STR)
            raise InvalidAlgorithm(msg)

    def verify_signature(self, data):
        """Verify the signature against the given data."""
        raise NotImplementedError('not implemented')

    def sign(self, data):
        """Sign some data."""
        raise NotImplementedError('not implemented')

    def read_pubkey(self, data):
        pubkey = serialization.load_ssh_public_key(data, default_backend())
        assert isinstance(pubkey.public_numbers(), self.PUBKEY_CLASS)
        self.pubkey = pubkey

    def read_privkey(self, data, password=None):
        privkey = serialization.load_pem_private_key(data, password,
                                                     default_backend())
        assert isinstance(privkey.private_numbers(), self.PRIVKEY_CLASS)
        self.privkey = privkey


class RSAAlgorithm(BaseAlgorithm):
    FORMAT_STR = String(ENC_SSH_RSA)
    PRIVKEY_CLASS = rsa.RSAPrivateNumbers
    PUBKEY_CLASS = rsa.RSAPublicNumbers
    def unpack_pubkey(self, stream):
        self._check_keytype(stream)
        e = MPInt.unpack_from(stream)
        n = MPInt.unpack_from(stream)
        self.pubkey = rsa.RSAPublicNumbers(e.value, n.value).public_key(default_backend())

    def pack_pubkey(self):
        return b''.join([
            self.FORMAT_STR.pack(),
            MPInt(self.pubkey.public_numbers().e).pack(),
            MPInt(self.pubkey.public_numbers().n).pack()
        ])

    def verify_signature(self, data):
        verifier = self.pubkey.verifier(
            self.signature_blob,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        verifier.update(data)
        return verifier.verify()

    def sign(self, data):
        signer = self.privkey.signer(
            PKCS1v15(),
            hashes.SHA1()
        )
        signer.update(data)
        signed = signer.finalize()
        return signed

class DSAAlgorithm(BaseAlgorithm):
    FORMAT_STR = String(ENC_SSH_DSS)
    PRIVKEY_CLASS = dsa.DSAPrivateNumbers
    PUBKEY_CLASS = dsa.DSAPublicNumbers
    def unpack_pubkey(self, stream):
        self._check_keytype(stream)
        p = MPInt.unpack_from(stream)
        q = MPInt.unpack_from(stream)
        g = MPInt.unpack_from(stream)
        params = dsa.DSAParameterNumbers(p.value, q.value, g.value)

        y = MPInt.unpack_from(stream)
        pubnums = dsa.DSAPublicNumbers(y.value, params)
        self.pubkey = pubnums.public_key(default_backend())

    def pack_pubkey(self):
        pubnums = self.pubkey.public_numbers()
        return b''.join([
            self.FORMAT_STR.pack(),
            MPInt(pubnums.parameter_numbers.p).pack(),
            MPInt(pubnums.parameter_numbers.q).pack(),
            MPInt(pubnums.parameter_numbers.g).pack(),
            MPInt(pubnums.y).pack(),
        ])

    def verify_signature(self, data):
        # convert to rfc6979 signature
        r, s = (
            int.from_bytes(self.signature_blob[:20], 'big'),
            int.from_bytes(self.signature_blob[20:], 'big')
        )
        blob = utils.encode_rfc6979_signature(r, s)


        verifier = self.pubkey.verifier(
            blob,
            hashes.SHA1()
        )
        verifier.update(data)
        verifier.verify()

    def sign(self, data):
        print('data={}'.format(data))
        privnum = self.privkey.private_numbers()
        pubnum = self.privkey.public_key().public_numbers()
        paramnum = pubnum.parameter_numbers
        print('private_numbers: 0x{:02X}'.format(privnum.x))
        # print('public_numbers: 0x{:02X}'.format(pubnum.y))
        # print('parameter_numbers: 0x{:02X}, 0x{:02X}, 0x{:02X}'.format(paramnum.p, paramnum.q, paramnum.g))
        signer = self.privkey.signer(
            hashes.SHA1()
        )
        signer.update(data)
        signed = signer.finalize()
        print('signed={}'.format(signed))
        r, s = utils.decode_rfc6979_signature(signed)
        print('r=0x{:02X}, s=0x{:02X}'.format(r, s))
        return b''.join([
            int(r).to_bytes(20, 'big'),
            int(s).to_bytes(20, 'big')
        ])



PUBLIC_KEY_PROTOCOLS = OrderedDict((
    (ENC_SSH_RSA, RSAAlgorithm),
    (ENC_SSH_DSS, DSAAlgorithm)
))


def get_asymmetric_algorithm(keytype):
    """Get the referenced public key type. If a signature_blob blob is included,
    validate it.
    """
    try:
        handler = PUBLIC_KEY_PROTOCOLS[keytype]
    except KeyError:
        raise UnsupportedKeyProtocol(keytype)
    return handler
