"""Create and un-create packets.

RFC 4253, Section 6.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from pyssh.constants import MAX_PACKET

import io
import os
import struct


_PACKETLENGTHS = struct.Struct('>IB')
U32 = struct.Struct('>I')
U8 = struct.Struct('>B')

_UINT_32_WRAP = 2**32


class PacketHandler(object):
    """Base class for building/reading packets. Has a sequence number that
    can be incremented mod u32_max and returned as a 4-byte bytes.
    """
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
        """Given a payload, create a packet:
            - compress
            - pad
            - encrypt
            - hash
        """
        if len(payload) > MAX_PACKET:
            raise ValueError('Message too long to send!')

        # first, the payload is compressed
        payload = self.compressor.compress(payload)

        # now pad to the nearest block size bytes. note that this includes the
        # length fields
        padded = self.pad_payload(payload)
        encrypted = self.encryptor.encrypt(padded)
        if self.hasher.ENCRYPT_FIRST:
            hmac = self.hasher.hash(self._sequence_pack() + encrypted)
        else:
            hmac = self.hasher.hash(self._sequence_pack() + payload)
        return encrypted + hmac

    def write_packet(self, writer, payload):
        """Writer should be a file-like object with a write() method.

        Payload should be the packet payload.
        """
        writer.write(self.create_packet(payload))

    @property
    def block_size(self):
        """The block size for the encryption.
        """
        return self.encryptor.block_size

    def pad_payload(self, payload):
        """Pad the (compressed) payload to the block size, with random data.

        Return the padded payload with the prefixed length values (packet size
        and padding size).
        """
        payload_size = len(payload)
        pad_size = 4 + self.block_size - ((payload_size + 9) % self.block_size)
        packet = (_PACKETLENGTHS.pack(payload_size + pad_size + 1, pad_size) +
                  payload + os.urandom(pad_size))
        return packet


class _Decryptor(object):
    """A helper class for decrypting packets."""
    def __init__(self, decryptor):
        self.encrypted = io.BytesIO()
        self.decrypted = io.BytesIO()
        self.decryptor = decryptor

    def read(self, reader, length=None, blocks=1):
        """Read either length bytes or blocks blocks. Store the encrypted and
        decryted values in their appropriate BytesIO objects.
        """
        if length:
            assert length % self.decryptor.block_size == 0
            enc = reader.read(length)
        else:
            enc = reader.read(self.decryptor.block_size*blocks)
        self.encrypted.write(enc)
        dec = self.decryptor.process_block(enc)
        self.decrypted.write(dec)
        return dec

    def __iter__(self):
        """This lets you do::

            decrypted, encrypted = my_decryptor

        """
        yield self.decrypted
        yield self.encrypted



class PacketReader(PacketHandler):
    """Reads in packets from the other end."""
    def __init__(self, decryptor, validator, decompressor):
        super(PacketReader, self).__init__()
        self.decryptor = decryptor
        self.validator = validator
        self.decompressor = decompressor

    def _decrypt_packet(self, reader):
        """Decrypt a packet.
        Reader should be a file-like object with a read() method. read() should
        accept a number of bytes and return that many.

        Returns a tuple of (io.BytesIO, io.BytesIO). They are seeked to the end
        for now, but that could change.
        """
        pair = _Decryptor(self.decryptor)
        first_block = pair.read(reader, blocks=1)
        packet_size = U32.unpack_from(first_block)[0]

        to_read = (packet_size - (self.decryptor.block_size - U32.size))

        pair.read(reader, length=to_read)

        return pair

    def validate_packet(self, encrypted, decrypted, mac):
        """Validate that the mac matches the packet."""
        if self.validator.ENCRYPT_FIRST:
            data = encrypted.getvalue()
        else:
            data = decrypted.getvalue()
        data = self._sequence_pack() + data
        self.validator.validate(data, mac)

    def read_packet(self, reader, hashed=False):
        """Read in a packet using the reader. If hashed, validate the hash with
        the following mac.
        """
        encrypted, decrypted = self._decrypt_packet(reader)

        if hashed:
            self.validate_packet(encrypted, decrypted,
                                 reader.read(self.validator.digest_size))

        decrypted.seek(0)
        packet_length = U32.unpack_from(decrypted.read(U32.size))[0]
        padding_length = U8.unpack_from(decrypted.read(U8.size))[0]
        payload = decrypted.read(packet_length - padding_length - 1)
        padding = decrypted.read(padding_length)
        assert len(padding) == padding_length
        return payload
