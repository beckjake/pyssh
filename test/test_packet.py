    
import unittest
import pytest
import io

from pyssh import packet
from pyssh.crypto import hashers, symmetric
from pyssh import compression

from builtins import int, bytes

class DummyCipher(object):
    def __init__(self, block_size):
        self.block_size = block_size


class TestPadding(unittest.TestCase):
    """Test padding messages to some length."""
    def _some_pad(self, num):
        encryptor = DummyCipher(num)
        hasher = object()
        compressor = object()
        builder = packet.PacketBuilder(encryptor, hasher, compressor)
        assert len(builder.pad_payload(b'\x00')) % num == 0

    def test_pad_8(self):
        self._some_pad(8)

    def test_pad_16(self):
        self._some_pad(16)

    def test_pad_12(self):
        self._some_pad(12)

    def test_pad_24(self):
        self._some_pad(24)

    def test_pad_32(self):
        self._some_pad(32)


class ROT128Cipher(symmetric.BaseCipher):
    NAME = 'rot128'
    def process_block(self, data):
        data = bytes(data)
        ret = []
        for byte in data:
            val = (byte + 128) % 256
            ret.append(bytes([val]))
        return b''.join(ret)

        # return b''.join((bytes[(c+128 % 256)] for c in bytes(data)))


class TestNoneBidi(unittest.TestCase):
    def setUp(self):
        encryptor = symmetric.NoneCipher(None, None, None)
        hasher = hashers.NoneHasher()
        compressor = compression.NoneCompressor()
        decryptor = symmetric.NoneCipher(None, None, None)
        validator = hashers.NoneHasher()
        decompressor = compression.NoneCompressor()
        self.builder = packet.PacketBuilder(encryptor, hasher, compressor)
        self.packet_reader = packet.PacketReader(decryptor, validator, decompressor)

    def test_create(self):
        payload = b'\x00'
        expect = b'\x00\x00\x00\x0C\x0A\x00'
        pad_size = 10
        built = self.builder.create_packet(payload)
        assert built.startswith(expect)
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader) == payload

    def test_toolong(self):
        payload = b'\x00'* (1024 * (1 ** 10))
        with pytest.raises(ValueError):
            self.builder.create_packet(payload)


class TestBidi(unittest.TestCase):
    def setUp(self):
        encryptor = ROT128Cipher()
        hasher = hashers.MD5Hasher(b'\x00'*16)
        compressor = compression.NoneCompressor()
        self.builder = packet.PacketBuilder(encryptor, hasher, compressor)
        decryptor = ROT128Cipher()
        validator = hashers.MD5Hasher(b'\x00'*16)
        decompressor = compression.NoneCompressor()
        self.packet_reader = packet.PacketReader(decryptor, validator, decompressor)

    # TODO: fix this test.
    @pytest.mark.xfail
    def test_create(self):
        payload = b'\x00\x01\x02\x03'
        expect = b'\x80\x80\x80\x8C\x87'
        built = self.builder.create_packet(payload)
        assert built.startswith(expect)
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader, True) == payload

    def test_write(self):
        payload = b'\x00\x01\x02\x03'
        expect = b'\x80\x80\x80\x8C\x87'
        writer = io.BytesIO(b'')
        self.builder.write_packet(writer, payload)
        assert writer.getvalue().startswith(expect)

    def test_read(self):
        payload = b'\x00\x01\x02\x03'
        built = b'\x80\x80\x80\x8C\x87\x80\x81\x82\x83\xE7\x76\x1C\x99\x89\x8C\x77\x9A\x7A\xBE\x1B\xB6\x63\x96\xBE\x9F\x83\x9B\x62\x37\x77\xC2\x72'
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader, True) == payload


class TestBidiETM(unittest.TestCase):
    def setUp(self):
        encryptor = ROT128Cipher()
        hasher = hashers.MD5ETMHasher(b'\x00'*16)
        compressor = compression.NoneCompressor()
        self.builder = packet.PacketBuilder(encryptor, hasher, compressor)
        decryptor = ROT128Cipher()
        validator = hashers.MD5ETMHasher(b'\x00'*16)
        decompressor = compression.NoneCompressor()
        self.packet_reader = packet.PacketReader(decryptor, validator, decompressor)

    def test_create(self):
        payload = b'\x00\x01\x02\x03'
        expect = b'\x80\x80\x80\x8C\x87'
        built = self.builder.create_packet(payload)
        assert built.startswith(expect)
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader, True) == payload

    def test_write(self):
        payload = b'\x00\x01\x02\x03'
        expect = b'\x80\x80\x80\x8C\x87'
        writer = io.BytesIO(b'')
        self.builder.write_packet(writer, payload)
        assert writer.getvalue().startswith(expect)

    def test_read(self):
        payload = b'\x00\x01\x02\x03'
        built = b'\x80\x80\x80\x8C\x87\x80\x81\x82\x83\x29\x8E\x35\x7D\xE0\x25\x37\x89\x98\xAF\x55\x42\x23\x00\xE8\x86\x07\xFE\x90\x41\xF8\xE1\x5D'
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader, True) == payload

