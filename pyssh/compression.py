"""Implement compressors.
"""
from __future__ import print_function, unicode_literals, division, absolute_import
from pyssh.constants import COMPRESSION_TYPE_ZLIB, COMPRESSION_TYPE_NONE
from collections import OrderedDict
import zlib

# TODO: zlib@openssh.org compression
# Probably handle it like PuTTY does (copy+pasted):
# 1: Before USERAUTH_ACCEPT is received, advertise "zlib,none" in KEXINIT.
# 2: If an incoming KEXINIT includes "zlib@openssh.com", remember that.
# 3: After receiving USERAUTH_ACCEPT, if the current compression algorithm is
#    "none" and KEXINIT contained "zlib@openssh.com", initiate key re-exchange.
# 4: In KEXINITs after receiving USERAUTH_ACCEPT, advertise
#    "zlib,zlib@openssh.com,none".
# this avoids the nasty race inherent in determining when it's "after"
# SSH_MSG_USERAUTH_SUCCESS was sent

class UnsupportedCompressorError(Exception):
    """Unsupported compression type"""
    def __init__(self, algorithm):
        self.algorithm = algorithm
        msg = 'Compression algorithm {} not supported'.format(algorithm)
        super(UnsupportedCompressorError, self).__init__(msg)


class BaseCompressor(object):
    """The compressor interface."""
    def compress(self, data):
        """Compress data. bytes -> bytes"""
        raise NotImplementedError('not implemented')

    def decompress(self, data):
        """Decompress data. bytes -> bytes"""
        raise NotImplementedError('not implemented')


class ZlibCompressor(BaseCompressor):
    """An implementation of 'zlib'."""
    def __init__(self):
        self.compressor = zlib.compressobj(9)
        self.decompressor = zlib.decompressobj()

    def compress(self, data):
        return (self.compressor.compress(data) +
                self.compressor.flush(zlib.Z_FULL_FLUSH))

    def decompress(self, data):
        return self.decompressor.decompress(data)


class NoneCompressor(BaseCompressor):
    """An implementation of 'none'."""
    def compress(self, data):
        return data

    def decompress(self, data):
        return data


COMPRESSION_METHODS = OrderedDict((
    (COMPRESSION_TYPE_NONE, NoneCompressor),
    (COMPRESSION_TYPE_ZLIB, ZlibCompressor)
))


def get_compressor(algorithm):
    """Look up the compressor for algorithm.

    :param bytes algorithm: the algorithm name
    :return compressor: An initialized compressor.
    """
    try:
        compressor = COMPRESSION_METHODS[algorithm]
    except KeyError:
        raise UnsupportedCompressorError(algorithm)
    return compressor()
