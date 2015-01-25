
import pytest
import unittest
from pyssh import compression

class TestNone(unittest.TestCase):
    def test_compress(self):
        compressor = compression.NoneCompressor()
        assert compressor.compress(b'a'*1024) == b'a'*1024

    def test_decompress(self):
        compressor = compression.NoneCompressor()
        assert compressor.decompress(b'a'*1024) == b'a'*1024


class TestZlibCompressor(unittest.TestCase):
    def test_compress(self):
        expect = (b'\x78\xDA\x4A\x4C\x1C\x05\xA3\x60\x14\x8C\x54\x00\x00\x00'
                  b'\x00\xFF\xFF')
        compressor = compression.ZlibCompressor()
        assert compressor.compress(b'a'*1024) == expect

    def test_decompress(self):
        data = (b'\x78\xDA\x4A\x4C\x1C\x05\xA3\x60\x14\x8C\x54\x00\x00\x00'
                b'\x00\xFF\xFF')
        expect = b'a'*1024
        compressor = compression.ZlibCompressor()
        assert compressor.decompress(data) == expect


class TestGetCompressor(unittest.TestCase):
    def test_none(self):
        got = compression.get_compressor(b'none')
        assert issubclass(got, compression.NoneCompressor)

    def test_zlib(self):
        got = compression.get_compressor(b'zlib')
        assert issubclass(got, compression.ZlibCompressor)

    def test_invalid(self):
        with pytest.raises(compression.UnsupportedCompressorError):
            compression.get_compressor(b'not-a-compressor')



