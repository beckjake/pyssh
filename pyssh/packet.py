"""Create and un-create packets.

RFC 4253, Section 6.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

from pyssh.constants import MAX_PACKET

import io
import logging
import os
import struct

LOG = logging.getLogger(__name__)

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

        LOG.debug('raw payload: {!r}'.format(payload))
        # first, the payload is compressed
        payload = self.compressor.compress(payload)
        LOG.debug('compressed payload: {!r}'.format(payload))

        if self.hasher.ENCRYPT_FIRST:
            msg = self.create_etm_packet(payload)
        else:
            msg = self.create_eam_packet(payload)
        LOG.debug('final message: {!r}'.format(msg))
        return msg

    def create_etm_packet(self, payload):
        """Create an ETM packet from a comrpessed payload.
        Pad, encrypt, and mac

        Return a sequence of bytes to be sent over a socket.
        """
        padded = self.pad_packet(payload, False)
        # in ETM mode, we don't encrypt the first 4 bytes (the length),
        # but we do hash it.
        encrypted = self.encryptor.process_block(padded[4:])
        LOG.debug('encrypted payload: {!r}'.format(encrypted))
        hmac = self.hasher.hash(self._sequence_pack() + padded[:4] + encrypted)
        LOG.debug('hmac: {!r}'.format(hmac))
        # and of course, that is part of the final product.
        return padded[:4] + encrypted + hmac

    def create_eam_packet(self, payload):
        """Create an EAM packet from a compressed payload.

        Pad, mac, and encrypt

        Return a sequence of bytes to be sent over a socket.
        """
        padded = self.pad_packet(payload, True)
        # encrypt the length as well
        encrypted = self.encryptor.process_block(padded)
        LOG.debug('encrypted payload: {!r}'.format(encrypted))
        hmac = self.hasher.hash(self._sequence_pack() + padded)
        LOG.debug('hmac: {!r}'.format(hmac))
        return encrypted + hmac

    def pad_packet(self, payload, include_len):
        """If include_len is true, it is going to be included in the encrypted
        packet. If not, it will not be included (and therefore, we don't have to
        include it in padding calculations).
        """
        to_pad = len(payload) + 1
        if include_len:
            to_pad += 4

        pad_size = self.block_size - (to_pad % self.block_size)
        if pad_size < 4:
            pad_size += self.block_size

        padded = (_PACKETLENGTHS.pack(len(payload) + 1 + pad_size, pad_size) +
                  payload + os.urandom(pad_size))

        LOG.debug('length-prefixed, padded: {!r}'.format(padded))

        return padded

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


class PacketReader(PacketHandler):
    """Reads in packets from the other end."""
    def __init__(self, decryptor, validator, decompressor):
        super(PacketReader, self).__init__()
        self.decryptor = decryptor
        self.validator = validator
        self.decompressor = decompressor

    def decrypt_etm_packet(self, reader):
        """Decrypt ETM (encrypt-then-mac) packets.

        :param reader: An object that provides a .read() method, intended to be
            a Transport.
        """
        # in ETM mode, the first 4 bytes are hashed but not encrypted
        length_as_bytes = reader.read(4)
        packet_length = U32.unpack_from(length_as_bytes)[0]
        # the body, encrypted
        body = reader.read(packet_length)
        LOG.debug('encrypted body: {!r}'.format(body))

        # hash the encrypted packet (length included)
        hmac = reader.read(self.validator.digest_size)
        LOG.debug('hmac: {!r}'.format(hmac))
        self.validator.validate(
            self._sequence_pack() + length_as_bytes + body,
            hmac
        )

        decrypted = io.BytesIO(self.decryptor.process_block(body))
        LOG.debug('decrypted packet: {!r}'.format(decrypted))
        # return decrypted payload
        return self._strip_padding(decrypted, packet_length)

    def decrypt_eam_packet(self, reader):
        """Decrypt EAM (encrypt-and-mac) packets.

        :param reader: An object that provides a .read() method, intended to be
            a Transport.
        """
        # in regular mode the first 4 bytes are encrypted but not hashed
        decrypted = io.BytesIO()
        # decrypt the first block, pull out the packet length for later
        first_block = self.decryptor.process_block(
            reader.read(self.decryptor.block_size)
        )
        LOG.debug('first block: {!r}'.format(first_block))
        packet_length = U32.unpack_from(first_block[:4])[0]
        decrypted.write(first_block)
        # decrypt the rest of the packet: length minus whatever we already read

        body = reader.read(packet_length - len(first_block[4:]))
        decrypted.write(self.decryptor.process_block(body))
        LOG.debug('decrypted packet: {!r}'.format(decrypted.getvalue()))

        # hash the decrypted packet (lengths + payload + padding)
        hmac = reader.read(self.validator.digest_size)
        LOG.debug('hmac: {!r}'.format(hmac))
        self.validator.validate(
            self._sequence_pack() + decrypted.getvalue(), hmac
        )

        decrypted.seek(4)
        # return decrypted payload
        return self._strip_padding(decrypted, packet_length)

    def _strip_padding(self, decrypted, packet_length):
        """Strip off padding and padding size field from a BytesIO containing
        a decrypted packet of packet_length. Includes sanity check on size.
        """
        padding_length = U8.unpack_from(decrypted.read(1))[0]
        # packet legngth is payload + padding length field + padding
        payload = decrypted.read(packet_length - (1 + padding_length))
        assert len(decrypted.read()) == padding_length
        return payload

    def read_packet(self, reader):
        """Read in a packet using the reader.
        """
        if self.validator.ENCRYPT_FIRST:
            payload = self.decrypt_etm_packet(reader)
        else:
            payload = self.decrypt_eam_packet(reader)
        LOG.debug('compressed packet payload: {!r}'.format(payload))
        payload = self.decompressor.decompress(payload)
        LOG.debug('decompressed packet payload: {!r}'.format(payload))
        return payload
