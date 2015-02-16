
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

class Object(object):
    pass


class TestPadding(unittest.TestCase):
    """Test padding messages to some length."""
    def _some_eam_pad(self, num):
        encryptor = DummyCipher(num)
        hasher = Object()
        hasher.ENCRYPT_FIRST = False
        compressor = Object()
        builder = packet.PacketBuilder(encryptor, hasher, compressor)
        padded_length = len(builder.pad_packet(b'\x00', True))

        assert padded_length % num == 0
        # secondary goal
        assert 4 <= (padded_length - 6) <= 4 + num

    def _some_etm_pad(self, num):
        encryptor = DummyCipher(num)
        hasher = Object()
        hasher.ENCRYPT_FIRST = True
        compressor = Object()
        builder = packet.PacketBuilder(encryptor, hasher, compressor)
        padded_length = len(builder.pad_packet(b'\x00', False))

        assert padded_length % num == 4
        # secondary goal
        assert 4 <= (padded_length - 6) <= 4 + num

    def _some_pad(self, num):
        self._some_etm_pad(num)
        self._some_eam_pad(num)

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
        built = self.builder.create_packet(payload)
        assert built.startswith(expect)
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader) == payload

    def test_toolong(self):
        payload = b'\x00'* (1024 * (2 ** 10))
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
    #@pytest.mark.xfail
    def test_create(self):
        payload = b'\x00\x01\x02\x03'
        expect = b'\x80\x80\x80\x8C\x87'
        built = self.builder.create_packet(payload)
        assert built.startswith(expect)
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader) == payload

    def test_write(self):
        payload = b'\x00\x01\x02\x03'
        expect = b'\x80\x80\x80\x8C\x87'
        writer = io.BytesIO(b'')
        self.builder.write_packet(writer, payload)
        assert writer.getvalue().startswith(expect)

    def test_read(self):
        payload = b'\x00\x01\x02\x03'
        built = b'\x80\x80\x80\x90\x8B\x80\x81\x82\x83\x82\x78\x13\xA9\xF4\x2A\xC4\x97\x6A\x8C\xE1\x4A\x99\xD7\xF1\xEA\x71\x91\x3B\x7E\xB2\xC8\xF1\x18\x93\xA8\x56'
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader) == payload


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
        expect = b'\x00\x00\x00\x10\x8B'
        built = self.builder.create_packet(payload)
        assert built.startswith(expect)
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader) == payload

    def test_write(self):
        payload = b'\x00\x01\x02\x03'
        expect = b'\x00\x00\x00\x10\x8B'
        writer = io.BytesIO(b'')
        self.builder.write_packet(writer, payload)
        assert writer.getvalue().startswith(expect)

    def test_read(self):
        payload = b'\x00\x01\x02\x03'
        built = b'\x00\x00\x00\x10\x8B\x80\x81\x82\x83\x6C\x0B\x80\x55\x11\xD0\xF1\x89\x0C\x53\x31\x67\x82\xBA\x6D\x2A\x7E\x57\x8D\xEB\xAB\xD5\x70\x83\x9C\xC5\x67'
        reader = io.BytesIO(built)
        assert self.packet_reader.read_packet(reader) == payload

