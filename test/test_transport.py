from __future__ import print_function, unicode_literals, division, absolute_import



import socket
import threading
import time
import unittest

import pytest

from pyssh import transport
from pyssh import packet


class DemoServer(threading.Thread):
    def __init__(self, reactions=None):
        print('DemoServer init start')
        super(DemoServer, self).__init__()
        self._socket = self._client = self.raw = None
        self.reactions = reactions or []
        self.die = False
        self.recvd = []
        self._port = None
        self.banner = b'SSH-2.0-blahserver'
        print('DemoServer init done')

    def close(self):
        self.die = True
        self.raw.close()
        self._client.close()
        self._socket.close()

    def join(self):
        try:
            self.close()
        except AttributeError:
            pass
        super(DemoServer, self).join()

    def _connect(self):
        self._socket = socket.socket()
        self._socket.bind(('localhost', 0))
        _, port = self._socket.getsockname()
        self._num_reactions = 0
        self._port = port
        self._socket.listen(0)
        self._client, _ = self._socket.accept()
        self.raw = transport.RawTransport(self._client)

    def _banners(self):
        self.recvd.append(self.raw._readline())
        self.raw._writeline(self.banner)

    def run(self):
        try:
            self._connect()
            try:
                self._banners()
                for reaction in self.reactions:
                    packet = self.raw._read_packet()
                    self.recvd.append(packet)
                    self.raw.write(reaction)
                    if self.die:
                        break
            except (transport.Killed, OSError):
                pass
            finally:
                self.close()
        except:
            import sys
            print(sys.exc_info())
            raise
        finally:
            self.die = True

    @property
    def closed(self):
        return self.die

    def listening_block(self):
        self.start()
        while not self._port and not self.die:
           time.sleep(0.1)
        if self.die:
            raise RuntimeError('died')
        return self._port


class TestRawTransport(unittest.TestCase):
    def setUp(self):
        self.server = DemoServer()

    def tearDown(self):
        self.server.join()

    def test_basic(self):
        port = self.server.listening_block()
        raw = transport.RawTransport.from_addr(('localhost', port))
        raw._writeline(b'SSH-2.0-blahclient')
        assert raw._readline(2) == b'SSH-2.0-blahserver'

    def test_nohandler_packet(self):
        self.server.reactions.append(b'\x00\x00\x00\x0C\x0A\x01\x14\x40\x9C\xBF\x22\x13\x52\x5F\x5D\x55')
        port = self.server.listening_block()
        raw = transport.RawTransport.from_addr(('localhost', port))

        raw._writeline(b'SSH-2.0-blahclient')
        raw._readline(2)
        raw._write_packet(b'\x00')
        payload = raw._read_packet()
        assert payload == b'\x01'

    def test_toolong_line(self):
        self.server.banner = b'A'*257
        port = self.server.listening_block()
        raw = transport.RawTransport.from_addr(('localhost', port))

        raw._writeline(b'SSH-2.0-blahclient')

        with pytest.raises(transport.Invalid):
            raw._readline(2)
        raw.close()
        self.server.join()

    def test_kill(self):
        self.server.reactions.append(b'\x00\x00\x00\x0C\x0A\x01\x14\x40\x9C\xBF\x22\x13\x52\x5F\x5D\x55')
        port = self.server.listening_block()
        raw = transport.RawTransport.from_addr(('localhost', port))

        raw._writeline(b'SSH-2.0-blahclient')
        raw._readline(2)

        self.server.join()
        raw._write_packet(b'hello')
        raw.close()


class TestTransport(unittest.TestCase):
    def setUp(self):
        self.server = DemoServer()

    def tearDown(self):
        self.server.join()

    def test_banner(self):
        port = self.server.listening_block()
        tpt = transport.Transport.from_addr(('localhost', port))
        tpt.banner_exchange()
        tpt.close()
        self.server.join()
        assert tpt._remote_banner == b'SSH-2.0-blahserver'

    def test_bad_version_server(self):
        self.server.banner = b'ASDF-1.0-test'
        port = self.server.listening_block()
        tpt = transport.Transport.from_addr(('localhost', port))
        with pytest.raises(transport.TransportError):
            tpt.banner_exchange(2)
        tpt.close()
        self.server.join()

    def test_bad_server(self):
        self.server.banner = b'ASDF'
        port = self.server.listening_block()
        tpt = transport.Transport.from_addr(('localhost', port))
        with pytest.raises(transport.TransportError):
            tpt.banner_exchange(2)
        tpt.close()
        self.server.join()

