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

from builtins import int #pylint: disable=redefined-builtin

from pyssh.constants import ENC_SSH_RSA, ENC_SSH_DSS
from pyssh.base_types import String, MPInt

# pylint:disable=invalid-name

class UnsupportedKeyProtocol(Exception):
    """Key protocol not supported."""


class InvalidAlgorithm(Exception):
    """Mismatched algorithm"""


#TODO: ECDSA (RFC 5656)
class BaseAlgorithm(object):
    """The base algorithm. Has private keys and/or public keys and does
    signature creation and/or verification.
    """
    FORMAT_STR = None
    PUBKEY_CLASS = None
    PRIVKEY_CLASS = None
    def __init__(self, privkey=None, pubkey=None):
        self._privkey = None
        self.privkey = privkey
        self.pubkey = pubkey

    @property
    def privkey(self):
        """Getter for the private key."""
        return self._privkey

    @privkey.setter
    def privkey(self, value):
        """When setting the private key, also set the public key to match."""
        self._privkey = value
        if value:
            self.pubkey = value.public_key()

    def unpack_pubkey(self, stream):
        """Unpack a public key from a stream."""
        raise NotImplementedError('not implemented')

    def pack_pubkey(self):
        """Pack a public key into bytes."""
        raise NotImplementedError('not implemented')

    @classmethod
    def _check_keytype(cls, stream):
        """Verify that the keytype from the stream is the expected one."""
        keytype = String.unpack_from(stream)
        if cls.FORMAT_STR != keytype:
            msg = 'Got {!r}, expected {!r}'.format(keytype, cls.FORMAT_STR)
            raise InvalidAlgorithm(msg)

    def verify_signature(self, signature, data):
        """Verify the signature against the given data. Pubkey must be set."""
        raise NotImplementedError('not implemented')

    def sign(self, data):
        """Sign some data. Privkey must be set."""
        raise NotImplementedError('not implemented')

    def read_pubkey(self, data):
        """Read a public key from data in the ssh public key format.

        :param bytes data: the data to read.
        Sets self.pubkey.
        """
        pubkey = serialization.load_ssh_public_key(data, default_backend())
        assert isinstance(pubkey.public_numbers(), self.PUBKEY_CLASS)
        self.pubkey = pubkey

    def read_privkey(self, data, password=None):
        """Read a PEM-encoded private key from data. If a password is set, it
        will be used to decode the key.

        :param bytes data: the data to read
        :param bytes password: The password.
        Sets self.privkey.
        """
        privkey = serialization.load_pem_private_key(data, password,
                                                     default_backend())
        assert isinstance(privkey.private_numbers(), self.PRIVKEY_CLASS)
        self.privkey = privkey


class RSAAlgorithm(BaseAlgorithm):
    """Support for the RSA algorithm."""
    FORMAT_STR = String(ENC_SSH_RSA)
    PRIVKEY_CLASS = rsa.RSAPrivateNumbers
    PUBKEY_CLASS = rsa.RSAPublicNumbers
    def unpack_pubkey(self, stream):
        self._check_keytype(stream)
        e = MPInt.unpack_from(stream).value
        n = MPInt.unpack_from(stream).value
        self.pubkey = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

    def pack_pubkey(self):
        return b''.join([
            self.FORMAT_STR.pack(),
            MPInt(self.pubkey.public_numbers().e).pack(),
            MPInt(self.pubkey.public_numbers().n).pack()
        ])

    def verify_signature(self, signature, data):
        stream = io.BytesIO(signature)
        self._check_keytype(stream)
        blob = String.unpack_from(stream).value
        verifier = self.pubkey.verifier(
            blob,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        verifier.update(data)
        verifier.verify()


    def sign(self, data):
        signer = self.privkey.signer(
            PKCS1v15(),
            hashes.SHA1()
        )
        signer.update(data)
        signed = signer.finalize()
        return b''.join([
            self.FORMAT_STR.pack(),
            String(signed).pack()
        ])


class DSAAlgorithm(BaseAlgorithm):
    """Support for the DSA."""
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

    def verify_signature(self, signature, data):
        stream = io.BytesIO(signature)
        self._check_keytype(stream)
        blob = String.unpack_from(stream).value

        # convert to rfc6979 signature
        blob = utils.encode_rfc6979_signature(
            r=int.from_bytes(blob[:20], 'big'),
            s=int.from_bytes(blob[20:], 'big')
        )

        verifier = self.pubkey.verifier(
            blob,
            hashes.SHA1()
        )
        verifier.update(data)
        verifier.verify()

    def sign(self, data):
        signer = self.privkey.signer(
            hashes.SHA1()
        )
        signer.update(data)
        signed = signer.finalize()
        r, s = utils.decode_rfc6979_signature(signed)
        return b''.join([
            self.FORMAT_STR.pack(),
            String(int(r).to_bytes(20, 'big') + int(s).to_bytes(20, 'big')).pack(),
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
    return handler()
