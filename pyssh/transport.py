"""Perform key exchange."""
from __future__ import print_function, unicode_literals, division, absolute_import

from collections import namedtuple, OrderedDict
import io
import socket
import threading
import time

from .crypto.hashers import NoneHasher
from .crypto.symmetric import NoneCipher
from .compression import NoneCompressor
from .packet import PacketBuilder, PacketReader
from .message import tpt
from .message import unpack_from, State

from .crypto.hashers import HASHES
from .crypto.symmetric import CIPHERS
from .crypto.asymmetric import PUBLIC_KEY_PROTOCOLS
from .compression import COMPRESSION_METHODS
from .kex import KEX_METHODS, get_kex_handler

from pyssh.base_types import NameList, Boolean
from pyssh.constants import SSH_IDENT_STRING

from logging import getLogger

LOG = getLogger(__name__)


class Killed(Exception):
    """Connection was killed."""


class Timeout(Exception):
    """Timed out"""



class Invalid(Exception):
    """Received invalid data."""


class TransportError(Exception):
    """Generic transport-level error."""


class RawTransport(object):
    """A raw transport. Knows about packets but not messages.
    """
    def __init__(self, sock):
        sock.settimeout(0.5)
        self._socket = sock
        self.packet_reader = PacketReader(
            NoneCipher(), NoneHasher(), NoneCompressor()
        )
        self.packet_builder = PacketBuilder(
            NoneCipher(), NoneHasher(), NoneCompressor()
        )
        self._socket_lock = threading.Lock()
        self.die = False

    def close(self):
        """Close the raw transport by marking the loop to end and closing the
        underlying socket.
        """
        self.die = True
        self._socket.close()

    @classmethod
    def from_addr(cls, addr):
        """Return a RawTransport based on a new socket to addr."""
        sock = socket.socket()
        sock.connect(addr)
        return cls(sock)

    def _safe_recv(self, num):
        """Receive num bytes, as long as die is not set."""
        if self.die:
            msg = 'killed waiting for {} bytes'
            raise Killed(msg.format(num))
        return self._socket.recv(num)

    def _safe_send(self, data):
        """Send the data, as long as die is not set."""
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
        """Write the payload as a packet."""
        self.packet_builder.write_packet(self, payload)

    def read_packet(self):
        """Read in a packet, returning its payload"""
        return self.packet_reader.read_packet(self)



_KEXINIT_NEGOTIATED_FIELDS = [
    'kex_method', 'server_host_key_algorithm',
    'cipher_client_to_server', 'cipher_server_to_client',
    'hash_client_to_server', 'hash_server_to_client',
    'comp_client_to_server', 'comp_server_to_client'
]

Negotiated = namedtuple('Negotiated', _KEXINIT_NEGOTIATED_FIELDS)

def _negotiate_attr(client, server, attr):
    """Negotiate a single attribute using the client and server messages.

    Return the negotiated value.
    Raises a TransportError if there are no common methods.
    """
    matches = [x for x in getattr(client, attr) if x in getattr(server, attr)]
    try:
        return matches[0]
    except IndexError:
        msg = 'Could not perform key exchange (no common {} methods)'
        msg = msg.format(attr)
        raise TransportError(msg)


def negotiate(client_msg, server_msg):
    """Negotiate all the attributes in Negotiated using the client and server
    messages.

    Return a Negotiated namedtuple.
    """
    return Negotiated(
        _negotiate_attr(client_msg, server_msg, 'kex_methods'),
        _negotiate_attr(client_msg, server_msg, 'server_host_key_algorithms'),
        _negotiate_attr(client_msg, server_msg, 'ciphers_client_to_server'),
        _negotiate_attr(client_msg, server_msg, 'ciphers_server_to_client'),
        _negotiate_attr(client_msg, server_msg, 'hashes_client_to_server'),
        _negotiate_attr(client_msg, server_msg, 'hashes_server_to_client'),
        _negotiate_attr(client_msg, server_msg, 'comp_client_to_server'),
        _negotiate_attr(client_msg, server_msg, 'comp_server_to_client')
    )


class Transport(object):
    """An implementation of the SSH Transport layer, as defined in RFC 4253"""
    LOCAL_BANNER = SSH_IDENT_STRING
    SERVER_LOCATION = None
    def __init__(self, raw):
        self._raw = raw
        self.state = State()
        self._remote_banner = None
        self._prefix = None

    @classmethod
    def from_addr(cls, addr):
        """Return a transport using an address."""
        return cls(RawTransport.from_addr(addr))

    def read_msg(self, types=None):
        """Read in a message from the remote system."""
        payload = self._raw.read_packet()
        msg = unpack_from(io.BytesIO(payload), self.state)
        if types:
            assert isinstance(msg, tuple(types))
        return msg

    def send_msg(self, msg):
        """Send a message to the remote system."""
        payload = msg.pack()
        self._raw.write_packet(payload)

    def _make_kexinit(self): # pylint:disable=no-self-use
        """Make the kexinit message.

        (self, kex_methods, server_host_key_algorithms,
                     ciphers_client_to_server, ciphers_server_to_client,
                     hashes_client_to_server, hashes_server_to_client,
                     comp_client_to_server, comp_server_to_client,
                     languages_client_to_server, languages_server_to_client,
                     first_kex_message_follows, random_data=None, reserved=None)
        """
        return tpt.KexInit(
            NameList(KEX_METHODS.keys()),
            NameList(PUBLIC_KEY_PROTOCOLS.keys()),
            NameList(CIPHERS.keys()),
            NameList(CIPHERS.keys()),
            NameList(HASHES.keys()),
            NameList(HASHES.keys()),
            NameList(COMPRESSION_METHODS.keys()),
            NameList(COMPRESSION_METHODS.keys()),
            NameList([b'en-us']),
            NameList([b'en-us']),
            Boolean(False)
        )

    def banner_exchange(self, timeout=30):
        """Exchange banners with the remote host. Get a banner out of it.
        """
        assert not self._remote_banner
        LOG.debug('Sent banner: {}'.format(self.LOCAL_BANNER))
        self._raw.writeline(self.LOCAL_BANNER)

        remote_banner = self._raw.readline(timeout)
        LOG.debug('Got banner: {}'.format(remote_banner))
        try:
            proto, protoversion, _ = remote_banner.split()[0].split(b'-')
        except ValueError:
            msg = 'Cannot connect to remote with banner {!r}'
            msg = msg.format(remote_banner)
            raise TransportError(msg)

        if proto != b'SSH' or protoversion not in (b'2.0', b'1.99'):
            msg = 'Conected to remote with invalid banner {!r}'
            msg = msg.format(remote_banner)
            raise TransportError(msg)
        self._remote_banner = remote_banner

    def _negotiate(self, local_msg, remote_msg):
        """Run the negotiation algorithm between local and remote messages."""
        raise NotImplementedError('implement in subclasses')

    def _send_kex_messages(self, remote_msg=None):
        """Send/receive KexInit.

        If remote_msg is not set, we didn't get it yet.
        """
        assert self._remote_banner
        self.state.in_kex = True
        local_msg = self._make_kexinit()
        LOG.debug('Sending local KEXINIT: {}'.format(local_msg))
        self.send_msg(local_msg)
        if remote_msg is None:
            remote_msg = self.read_msg()
            LOG.debug('Got remote msg: {}'.format(remote_msg))
        else:
            LOG.debug('Using existing remote msg: {}'.format(local_msg))
        self._prefix = b''.join((self.LOCAL_BANNER, self._remote_banner,
                                 local_msg.pack(), remote_msg.pack()))
        return self._negotiate(local_msg, remote_msg)

    def start_kex(self):
        """Start the key exchange process, unilaterally."""
        negotiated = self._send_kex_messages()
        kex_handler = get_kex_handler(negotiated.kex_method)
        self.state.kex_method = negotiated.kex_method
        kex_handler = kex_handler(negotiated, self._prefix)
        # delegate performing the exchange to the handler - it will only know
        # about sending and receiving messages.
        kex_state = kex_handler.start_exchange(self)
        self.send_msg(tpt.KexNewkeys())
        self._raw.packet_builder = kex_state.get_builder()
        # TODO: more stuff
        self.wait_for_newkeys(kex_state)
        self.state.in_kex = False

    def wait_for_newkeys(self, kex_state):
        """Wait for the KexNewkeys message."""
        while True:
            recvd = self.read_msg()
            if isinstance(recvd, tpt.KexNewkeys):
                self._raw.packet_reader = kex_state.get_reader()
                return
            else:
                raise NotImplementedError('TODO: handle this')


class ClientTransport(Transport):
    """A client-side Transport."""
    def _negotiate(self, local_msg, remote_msg):
        return negotiate(local_msg, remote_msg)


class ServerTransport(Transport):
    """A server-side Transport."""
    # map host keytype -> host key
    HOST_KEYS = OrderedDict()
    def _negotiate(self, local_msg, remote_msg):
        return negotiate(remote_msg, local_msg)

    def get_host_privkey(self, key_type):
        """Retrieve the host private key, based on the specified key type."""
        return self.HOST_KEYS[key_type]

