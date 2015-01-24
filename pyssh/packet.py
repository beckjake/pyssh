"""Create and un-create packets.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from pyssh.constants import MAX_PACKET
from pyssh.base_types import UInt32

from collections import namedtuple
import io
import os
import struct


_PacketLengths = struct.Struct('>IB')
U32 = struct.Struct('>I')
U8 = struct.Struct('>B')

_UINT_32_WRAP = 2**32


class PacketHandler(object):
    def __init__(self):
        self.sequence_number = 0

    def _sequence_pack(self):
        """Pack the sequence number into a UInt32, then increment by 1."""
        packed = U32.pack(self.sequence_number)
        self.sequence_number = (self.sequence_number + 1) % _UINT_32_WRAP
        return packed



class PacketBuilder(PacketHandler):
    """The PacketBuilder is responsible for building packets for sending.
    It does NOT know how to un-build a packet (that is done by PacketReader).
    It does NOT know about messages, it is only given payloads of data and told
    to "make it so".

    TODO: Thread locking around create_packet
    """
    def __init__(self, encryptor, hasher, compressor):
        super(PacketBuilder, self).__init__()
        self.encryptor = encryptor
        self.hasher = hasher
        self.compressor = compressor

    def create_packet(self, payload):
        if len(payload) > MAX_PACKET:
            raise ValueError('Message too long to send!')

        # first, the payload is compressed
        payload = self.compressor.compress(payload)

        # now pad to the nearest block size bytes. note that this includes the
        # length fields
        padded = self.pad_payload(payload)
        encrypted = self.encryptor.process_block(padded)
        # some hashes ('-etm') require the encryption to occur first.
        if self.hasher.ENCRYPT_FIRST:
            hmac = self.hasher.hash(self._sequence_pack() + encrypted)
        else:
            hmac = self.hasher.hash(self._sequence_pack() + padded)
        return encrypted + hmac

    def write_packet(self, writer, payload):
        writer.write(self.create_packet(payload))

    @property
    def block_size(self):
        return self.encryptor.block_size

    def pad_payload(self, payload):
        """Pad the (compressed) payload to the block size, with random data.

        Return the padded payload with the prefixed length values (packet size
        and padding size).
        """
        payload_size = len(payload)
        pad_size = 4 + self.block_size - ((payload_size + 9) % self.block_size)
        packet = (_PacketLengths.pack(payload_size + pad_size + 1, pad_size) +
                  payload + os.urandom(pad_size))
        return packet


class PacketReader(PacketHandler):
    def __init__(self, decryptor, validator, decompressor):
        super(PacketReader, self).__init__()
        self.decryptor = decryptor
        self.validator = validator
        self.decompressor = decompressor

    def decrypt_packet(self, reader):
        """Decrypt a packet."""
        first_block_e = reader.read(self.decryptor.block_size)
        first_block = self.decryptor.process_block(first_block_e)
        packet_size = U32.unpack_from(first_block)[0]

        to_read = (packet_size - (self.decryptor.block_size - U32.size))

        encrypted = io.BytesIO(b'')
        encrypted.write(first_block_e)
        encrypted.write(reader.read(to_read))
        decrypted = io.BytesIO(b'')
        decrypted.write(first_block)
        encrypted.seek(self.decryptor.block_size)
        decrypted.write(self.decryptor.process_block(encrypted.read()))
        assert decrypted.tell() == encrypted.tell()
        return decrypted, encrypted

    def validate_packet(self, data, mac):
        data = self._sequence_pack() + data
        self.validator.validate(data, mac)

    def read_packet(self, reader):
        decrypted, encrypted = self.decrypt_packet(reader)

        if self.validator.ENCRYPT_FIRST:
            to_hash = encrypted
        else:
            to_hash = decrypted

        self.validate_packet(to_hash.getvalue(),
                             reader.read(self.validator.digest_size))

        decrypted.seek(0)
        packet_length = U32.unpack_from(decrypted.read(U32.size))[0]
        padding_length = U8.unpack_from(decrypted.read(U8.size))[0]
        payload = decrypted.read(packet_length - padding_length - 1)
        padding = decrypted.read(padding_length)
        assert len(padding) == padding_length
        return payload
