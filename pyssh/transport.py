"""Perform key exchange."""
from __future__ import print_function, unicode_literals, division, absolute_import

from collections import namedtuple
import io
import socket
import threading
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, SHA1



from .constants import (KEX_DH_GROUP1_SHA1, KEX_DH_GROUP14_SHA1,
                        KEX_DH_GROUP1_P, KEX_DH_GROUP1_G,
                        KEX_DH_GROUP14_P, KEX_DH_GROUP14_G,
                        SSH_IDENT_STRING
                        )

from .crypto.hashers import get_hasher
from .crypto.asymmetric import get_public_key
from .crypto.symmetric import get_cipher
from .compression import get_compressor

from .crypto.hashers import NoneHasher
from .crypto.symmetric import NoneCipher
from .compression import NoneCompressor
from .packet import PacketBuilder, PacketReader

from pyssh.base_types import Direction

class Killed(Exception):
    """Connection was killed."""


class Timeout(Exception):
    """Timed out"""


class Invalid(Exception):
    pass


class TransportError(Exception):
    pass


# class Invalid(Exception):
#     """Invalid data."""
#     def __init__(self, msg, buf):
#         self.buffer = buf
#         super(Invalid, self).__init__(msg)

_KEXINIT_NEGOTIATED_FIELDS = [
    'kex_method', 'server_host_key_algorithm',
    'cipher_client_to_server', 'cipher_server_to_client',
    'hash_client_to_server', 'hash_server_to_client',
    'comp_client_to_server', 'comp_server_to_client'
]

Negotiated = namedtuple('Negotiated', _KEXINIT_NEGOTIATED_FIELDS)


class BaseKexState(object):
    C_TO_S = None
    S_TO_C = None
    def __init__(self, hash_algorithm, K, H, negotiated, session_id=None):
        self.hash_algorithm = hash_algorithm
        self.K = K
        self.H = H
        self.negotiated = negotiated
        self.session_id = self.H if session_id is None else session_id

    @property
    def K(self):
        return self._K

    @K.setter
    def K(self, value):
        self._K = value
        self._KPacked = value.pack()

    def _hash_iter(self, start, keysize):
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
        assert len(keychar) == 1
        start = keychar + self.session_id
        return b''.join(_hash_iter(K.pack(), H, start, keysize))

    def get_client_to_server_cipher(self):
        cls = get_cipher(self.negotiated.cipher_client_to_server)
        iv = self._create_key(b'A', cls.block_size)
        key = self._create_key(b'C', cls.block_size)
        return cls(key, iv, self.C_TO_S)

    def get_server_to_client_cipher(self):
        cls = get_cipher(self.negotiated.cipher_server_to_client)
        iv = self._create_key(b'B', cls.block_size)
        key = self._create_key(b'D', cls.block_size)
        return cls(key, iv, self.S_TO_C)

    def get_client_to_server_hasher(self):
        cls = get_hasher(self.negotiated.hash_client_to_server)
        iv = self._create_key(b'E', cls.block_size)
        return cls(iv)

    def get_server_to_client_hasher(self):
        cls = get_hasher(self.negotiated.hash_server_to_client)
        iv = self._create_key(b'F', cls.block_size)
        return cls(iv)

    def get_client_to_server_compressor(self):
        cls = get_compressor(self.negotiated.comp_client_to_server)
        return cls()

    def get_server_to_client_compressor(self):
        cls = get_compressor(self.negotiated.comp_server_to_client)
        return cls()

    def get_builder(self):
        """Make a PacketBuilder for writing.
        """
        raise NotImplementedError('implement in child class')

    def get_handler(self):
        """Make a PacketReader for writing.
        """
        raise NotImplementedError('implement in child class')



class ClientKexState(BaseKexState):
    C_TO_S = Direction.outbound
    S_TO_C = Direction.inbound
    def get_builder(self):
        encryptor = self.get_client_to_server_cipher()
        hasher = self.get_client_to_server_hasher()
        compressor = self.get_client_to_server_compressor()
        return PacketBuilder(encryptor, hasher, compressor)

    def get_handler(self):
        decryptor = self.get_server_to_client_cipher()
        validator = self.get_server_to_client_hasher()
        decompressor = self.get_server_to_client_compressor()
        return PacketReader(decryptor, validator, decompressor)


class ServerKexState(BaseKexState):
    C_TO_S = Direction.inbound
    S_TO_C = Direction.outbound
    def get_builder(self):
        encryptor = self.get_server_to_client_cipher()
        validator = self.get_server_to_client_hasher()
        compressor = self.get_server_to_client_compressor()
        return PacketBuilder(encryptor, hasher, compressor)

    def get_handler(self):
        decryptor = self.get_client_to_server_cipher()
        validator = self.get_client_to_server_hasher()
        decompressor = self.get_client_to_server_compressor()
        return PacketReader(decryptor, validator, decompressor)


class RawTransport(object):
    def __init__(self, sock):
        sock.settimeout(0.5)
        self._socket = sock
        self.packet_handler = PacketReader(NoneCipher(), NoneHasher(),
                                           NoneCompressor())
        self.packet_builder = PacketBuilder(NoneCipher(), NoneHasher(),
                                            NoneCompressor())
        self._socket_lock = threading.Lock()
        self.die = False

    def close(self):
        self.die = True
        self._socket.close()

    @classmethod
    def from_addr(cls, addr):
        sock = socket.socket()
        sock.connect(addr)
        return cls(sock)

    def _safe_recv(self, num):
        if self.die:
            msg = 'killed waiting for {} bytes'
            raise Killed(msg.format(num))
        return self._socket.recv(num)

    def _safe_send(self, data):
        if self.die:
            msg = 'Killed while trying to write {} bytes'
            raise Killed(msg.format(len(data)))
        return self._socket.send(data)

    def write(self, data):
        """Write all data."""
        with self._socket_lock:
            sofar = 0
            to_send = len(data)
            while sofar < to_send:
                sent = self._safe_send(data[:(to_send-sofar)])
                sofar += sent

    def writeline(self, data):
        """Write a line."""
        self.write(data + b'\r\n')

    def read(self, num_bytes):
        """Read num_bytes of data."""
        with self._socket_lock:
            buf = b''
            remaining = num_bytes
            while remaining:
                recvd = self._safe_recv(remaining)
                buf += recvd
                remaining -= len(recvd)
            return buf

    def readline(self, timeout=30):
        """Receive bytes until a crlf, or timeout s.
        """
        with self._socket_lock:
            crlf = b'\r\n'
            buf = io.BytesIO(b'')
            start = time.time()
            ret = buf.getvalue()
            initial_timeout = self._socket.gettimeout()
            self._socket.settimeout(timeout)
            try:
                while crlf not in ret and buf.tell() < 256:
                    buf.write(self._safe_recv(256 - buf.tell()))
                    if time.time() >= (start + timeout):
                        raise Timeout('Took {}s, no crlf'.format(time.time() - start))
                    ret = buf.getvalue()
                if buf.tell() > 256 or not ret.endswith(crlf):
                    raise Invalid('too much data, no CRLF', ret)
                return ret.rstrip()
            finally:
                self._socket.settimeout(initial_timeout)

    def write_packet(self, payload):
        self.packet_builder.write_packet(self, payload)

    def read_packet(self):
        return self.packet_handler.read_packet(self)


class Transport(object):
    """An implementation of the SSH Transport layer, as defined in RFC 4253"""
    def __init__(self, raw):
        self._raw = raw

    @classmethod
    def from_addr(cls, addr):
        return cls(RawTransport.from_addr(addr))

    def read_packet(self):
        return self._raw.read_packet()

    def write_packet(self, payload):
        self._raw.write_packet(payload)

    def banner_exchange(self, timeout=30):
        """Exchange banners with the remote host. Get a banner out of it.
        """
        client = SSH_IDENT_STRING
        self._raw.writeline(client)

        server = self._raw.readline(timeout)
        try:
            proto, protoversion, _ = server.split()[0].split(b'-')
        except ValueError:
            raise TransportError('Cannot connect to server with banner {!r}'.format(server))

        if proto != b'SSH' or protoversion not in (b'2.0', b'1.99'):
            raise TransportError('Conected to server with invalid banner {!r}'.format(server))
        return client, server



# class Server(object):
#     def __init__(self, transport):
#         self._transport = transport

