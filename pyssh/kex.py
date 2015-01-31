"""Methods and helpers for key exchange.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

import io
from collections import OrderedDict
from random import SystemRandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, SHA1



from .crypto.hashers import get_hasher
from .crypto.asymmetric import get_asymmetric_algorithm
from .crypto.symmetric import get_cipher
from .compression import get_compressor
from .packet import PacketBuilder, PacketReader

from pyssh.constants import (
    KEX_DH_GROUP1_SHA1, KEX_DH_GROUP14_SHA1,
    KEX_DH_GROUP1_P, KEX_DH_GROUP1_G,
    KEX_DH_GROUP14_P, KEX_DH_GROUP14_G)
from pyssh.base_types import Direction, MPInt, String
from pyssh.message import tpt

SYS_RANDOM = SystemRandom()

class InvalidKexMethod(Exception):
    """The kex method specified was invalid."""

# pylint:disable=invalid-name,too-many-arguments

class BaseKexState(object):
    """The base Key exchange state."""
    C_TO_S = None
    S_TO_C = None
    def __init__(self, hash_algorithm, K, H, negotiated, session_id=None):
        self.hash_algorithm = hash_algorithm
        self._K = self._KPacked = None
        self.K = K
        self.H = H
        self.negotiated = negotiated
        self.session_id = self.H if session_id is None else session_id

    @property
    def K(self):
        """store k both packed and unpacked."""
        return self._K

    @K.setter
    def K(self, value):
        """Setter for K."""
        self._K = value
        self._KPacked = value.pack()

    def _hash_iter(self, start, keysize):
        """Use the iterative hashing algorithm to generate up the keysize."""
        digest_size = self.hash_algorithm.digest_size
        data = start
        sofar = 0
        while sofar < keysize:
            digest = Hash(self.hash_algorithm, default_backend())
            digest.update(self._KPacked)
            digest.update(self.H)
            digest.update(data)
            data = digest.finalize()
            yield data[:keysize-sofar]
            sofar += digest_size

    def _create_key(self, keychar, keysize):
        """Create a certain key."""
        assert len(keychar) == 1
        start = keychar + self.session_id
        return b''.join(self._hash_iter(start, keysize))

    def get_client_to_server_cipher(self):
        """Get the cipher from client to server."""
        cls = get_cipher(self.negotiated.cipher_client_to_server)
        iv = self._create_key(b'A', cls.block_size)
        key = self._create_key(b'C', cls.KEY_SIZE)
        return cls(key, iv, self.C_TO_S)

    def get_server_to_client_cipher(self):
        """Get the cipher from server to client"""
        cls = get_cipher(self.negotiated.cipher_server_to_client)
        iv = self._create_key(b'B', cls.block_size)
        key = self._create_key(b'D', cls.KEY_SIZE)
        return cls(key, iv, self.S_TO_C)

    def get_client_to_server_hasher(self):
        """Get the hasher from client to server."""
        cls = get_hasher(self.negotiated.hash_client_to_server)
        iv = self._create_key(b'E', cls.iv_size)
        return cls(iv)

    def get_server_to_client_hasher(self):
        """Get the hasher from server to client"""
        cls = get_hasher(self.negotiated.hash_server_to_client)
        iv = self._create_key(b'F', cls.iv_size)
        return cls(iv)

    def get_client_to_server_compressor(self):
        """Get the compressor from client to server."""
        cls = get_compressor(self.negotiated.comp_client_to_server)
        return cls()

    def get_server_to_client_compressor(self):
        """Get the compressor from server to client"""
        cls = get_compressor(self.negotiated.comp_server_to_client)
        return cls()

    def get_builder(self):
        """Make a PacketBuilder for writing.
        """
        raise NotImplementedError('implement in child class')

    def get_reader(self):
        """Make a PacketReader for writing.
        """
        raise NotImplementedError('implement in child class')



class ClientKexState(BaseKexState):
    """The kex state for clients."""
    C_TO_S = Direction.outbound
    S_TO_C = Direction.inbound
    def get_builder(self):
        encryptor = self.get_client_to_server_cipher()
        hasher = self.get_client_to_server_hasher()
        compressor = self.get_client_to_server_compressor()
        return PacketBuilder(encryptor, hasher, compressor)

    def get_reader(self):
        decryptor = self.get_server_to_client_cipher()
        validator = self.get_server_to_client_hasher()
        decompressor = self.get_server_to_client_compressor()
        return PacketReader(decryptor, validator, decompressor)


class ServerKexState(BaseKexState):
    """The kex state for servers."""
    C_TO_S = Direction.inbound
    S_TO_C = Direction.outbound
    def get_builder(self):
        encryptor = self.get_server_to_client_cipher()
        hasher = self.get_server_to_client_hasher()
        compressor = self.get_server_to_client_compressor()
        return PacketBuilder(encryptor, hasher, compressor)

    def get_reader(self):
        decryptor = self.get_client_to_server_cipher()
        validator = self.get_client_to_server_hasher()
        decompressor = self.get_client_to_server_compressor()
        return PacketReader(decryptor, validator, decompressor)



class BaseMethod(object):
    """The base class for implementing key exchange methods.

    negotiated is a Negotiated namedtuple
    prefix is the sequence of bytes representing

        (V_C || V_S || I_C || I_S) as defined in RFC 4253, Section 8
    """
    def __init__(self, negotiated, prefix, session_id=None):
        self.negotiated = negotiated
        self.prefix = prefix
        self.session_id = session_id

    def start_exchange(self, transport):
        """Initiate the key exchange chosen in self.negotiated.kex_method
        using the transport.
        """
        raise NotImplementedError('not implemented')

    def wait_exchange(self, transport):
        """Wait for the remote side to initiate the key exchange chosen in
        self.negotiated.kex_method using the transport.
        """
        raise NotImplementedError('not implemented')

class _DiffieHellManGroupSha1Method(BaseMethod):
    """The base class for Diffie-Hellman Group X SHA1 methods."""
    P = None
    G = None
    NAME = None
    HASH = SHA1()
    INIT_CLS = None
    REPLY_CLS = None
    def _make_kexdh_init_values(self):
        """Make a KexDHInit packet

        See RFC 4253, section 8! "C generates a random number x (1 < x < q)..."
        P = 2Q + 1 -> Q = (P-1)/2 =>
        Q-1 = (P-1)/2 - 1 = (P - 3)/2

        note that this is using a SystemRandom, NOT the random module
        """
        x = SYS_RANDOM.randint(2, (self.P - 3)//2)
        e = pow(self.G, x, self.P)
        return e, x

    def _calculate_kexdh_hash(self, host_key, e, f, K):
        """Calculate the hash H."""

        # H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
        digest = Hash(self.HASH, default_backend())
        digest.update(self.prefix)
        digest.update(host_key.pack())
        digest.update(e.pack())
        digest.update(f.pack())
        digest.update(K.pack())
        return String(digest.finalize())

    def _make_kexdh_reply_values(self, kex_dh_init):
        """S generates a random number y (0 < y < q) and computes f = g^y mod p.
        S receives e.
        It computes K = e^y mod p, ...and signature s on H with its private host
        key.
        """
        y = SYS_RANDOM.randint(1, (self.P - 3)//2)
        f = MPInt(pow(self.G, y, self.P))
        K = MPInt(pow(kex_dh_init.e.value, y, self.P))
        return y, f, K

    def wait_exchange(self, transport):
        """Perform the server side of key exchange."""
        key_type = self.negotiated.server_host_key_algorithm
        algorithm = get_asymmetric_algorithm(key_type)
        algorithm.privkey = transport.get_host_privkey(key_type)

        kex_dh_init = transport.read_msg(types=[tpt.KexDHInit])
        _, f, K = self._make_kexdh_reply_values(kex_dh_init)

        k_s = String(algorithm.pack_pubkey())
        H = self._calculate_kexdh_hash(k_s, kex_dh_init.e, f, K)

        h_sig = String(algorithm.sign(H))
        kex_dh_reply = self.REPLY_CLS(k_s, f, h_sig) # pylint:disable=not-callable
        transport.send_msg(kex_dh_reply)
        if self.session_id is None:
            self.session_id = H
        return ServerKexState(self.HASH, K, H, self.negotiated, self.session_id)

    def start_exchange(self, transport):
        """Perform the key exchange using the transport and the negotiated
        parameters.
        """
        e, x = self._make_kexdh_init_values()
        kex_dh_init = self.INIT_CLS(MPInt(e)) # pylint:disable=not-callable
        transport.send_msg(kex_dh_init)
        kex_dh_reply = transport.read_msg(types=[tpt.KexDHReply])

        K = MPInt(pow(e, x, self.P))
        H = self._calculate_kexdh_hash(
            kex_dh_reply.k_s,
            kex_dh_init.e,
            kex_dh_reply.f,
            K
        )

        key_type = self.negotiated.server_host_key_algorithm
        algorithm = get_asymmetric_algorithm(key_type)
        algorithm.unpack_pubkey(io.BytesIO(kex_dh_reply.k_s.value))
        algorithm.verify(kex_dh_reply.h_sig.value, H)

        if self.session_id is None:
            self.session_id = H
        return ClientKexState(self.HASH, K, H, self.negotiated, self.session_id)


class DiffieHellmanGroup14Sha1(_DiffieHellManGroupSha1Method):
    """Concrete implementation of the DH Group 14 SHA1 algorithm."""
    P = KEX_DH_GROUP14_P
    G = KEX_DH_GROUP14_G
    NAME = KEX_DH_GROUP14_SHA1
    INIT_CLS = tpt.KexDHGroup14Init
    REPLY_CLS = tpt.KexDHGroup14Reply


class DiffieHellmanGroup1Sha1(_DiffieHellManGroupSha1Method):
    """Concrete implementation of the DH Group 1 SHA1 algorithm."""
    P = KEX_DH_GROUP1_P
    G = KEX_DH_GROUP1_G
    NAME = KEX_DH_GROUP1_SHA1
    INIT_CLS = tpt.KexDHGroup1Init
    REPLY_CLS = tpt.KexDHGroup1Reply


KEX_METHODS = OrderedDict((
    (KEX_DH_GROUP14_SHA1, DiffieHellmanGroup14Sha1),
    (KEX_DH_GROUP1_SHA1, DiffieHellmanGroup1Sha1)
))



def get_kex_handler(kex_method):
    """Get the kex handler specified."""
    try:
        return KEX_METHODS[kex_method]
    except KeyError:
        raise InvalidKexMethod('No method {} known'.format(kex_method))

