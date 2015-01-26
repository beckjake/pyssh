"""SSH Protocol base types.

"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals

import math
import struct

# python-future
from builtins import int, bytes #pylint: disable=redefined-builtin
# enum34
import enum


# pylint: disable=too-few-public-methods

### Just some utility things.
UINT_64 = struct.Struct(b'>Q')
UINT_32 = struct.Struct(b'>I')
UINT_8 = struct.Struct(b'>B')


def compact_bit_pack(value, signed):
    """Pack an integer into its most compact representation as a stream of bytes."""
    byte_length = int(math.ceil((value.bit_length()+1)/8))
    as_bytes = value.to_bytes(byte_length, 'big', signed=signed)
    return as_bytes


class classproperty(object): #pylint:disable=C0103
    """A getters-only classproperty."""
    def __init__(self, func):
        # make it a classmethod
        if not isinstance(func, (staticmethod, classmethod)):
            func = classmethod(func)
        self.func = func

    def __get__(self, obj, cls=None):
        # if we got an object but not its type, get its type.
        if cls is None:
            cls = type(obj)
        return self.func.__get__(obj, cls)()


### end utility things
class InsufficientDataError(Exception):
    """Didn't get enough data"""


class Packable(object):
    """Base for all types that provide a .pack() method.
    """
    def pack(self):
        """Pack the type into a bytes object.

        :return bytes: The packed data type.
        """
        raise NotImplementedError('Must implement in subclass')


class BaseType(Packable): # pylint: disable=W0223
    """Subclass for all protocol base types.
    """
    def __init__(self, value):
        self.value = value

    @classmethod
    def unpack_from(cls, stream):
        raise NotImplementedError('Must implement in subclass')

    def __str__(self):
        return '{}({!r})'.format(self.__class__.__name__, self.value)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError('Not the same, cannot compare')
        return self.value == other.value

    def __ne__(self, other):
        return not self.__eq__(other)


    def __hash__(self):
        return self.value.__hash__()



class RawByte16(BaseType):
    def pack(self):
        return self.value

    @classmethod
    def unpack_from(cls, stream):
        value = stream.read(16)
        if len(value) != 16:
            msg = 'ran out of data, got {} expected 16'
            msg = msg.format(len(value))
            raise InsufficientDataError('')
        return cls(value)


class _Struct(BaseType):
    """The base type for types that make use of a struct.

    This is an implementation detail, not part of the model.
    """
    _STRUCT = None
    def __init__(self, value):
        if isinstance(value, _Struct):
            value = value.value
        super(_Struct, self).__init__(int(value))

    @classproperty
    def size(cls):
        """Get the size, based on the struct.
        """
        return cls._STRUCT.size

    def pack(self):
        return self._STRUCT.pack(self.value)

    @classmethod
    def unpack_from(cls, stream):
        return cls(cls._STRUCT.unpack_from(stream.read(cls.size))[0])


class Byte(_Struct):
    """1-byte int"""
    _STRUCT = UINT_8


class Boolean(Byte):
    """Booleans get coerced into ints, but are stored as whatever we got them
    as by default. You can call fix() to set it to 1 if it isn't valid.
    """
    def pack(self):
        assert self.value in (0, 1)
        return super(Boolean, self).pack()

    def fix(self):
        """Fix the bool's value to be a bool if it wasn't already."""
        self.value = int(bool(self.value != 0))
        return self



class UInt32(_Struct):
    """4-byte int"""
    _STRUCT = UINT_32

class UInt64(_Struct):
    """8-byte int"""
    _STRUCT = UINT_64


class _LPrefixed(BaseType):
    """The base type for types that make use of a UINT_32 length-prefixed byte
    string.

    This is an implementation detail, not part of the model.
    """
    def _packdata(self):
        """This should return just the data portion of the packed object,
        without the length prefix.
        """
        raise NotImplementedError('Not implemented in base class')

    def pack(self):
        data = self._packdata()
        return b''.join([UINT_32.pack(len(data)), data])

    @classmethod
    def _unpackdata(cls, data):
        """Given the block of data unpacked after the length prefix, return
        an instance of the class. Data should be exactly as large as the prefix
        indicated.
        """
        raise NotImplementedError('Not implemented in base class')

    @classmethod
    def unpack_from(cls, stream):
        length = UINT_32.unpack_from(stream.read(UINT_32.size))[0]
        value = stream.read(length)
        if len(value) != length:
            msg = 'ran out of data, got {} expected {}'
            msg = msg.format(len(value), length)
            raise InsufficientDataError(msg)
        return cls._unpackdata(value)


class String(_LPrefixed):
    """Strings are specified to be allowed to contain arbitrary data, so they
    are stored as bytes objects.

    Most of the time data is specified as having an encoding of utf-8, and a
    minority of the time is specified as having an encoding of ascii (in the
    Python sense of [0, .., 127]).
    Therefore, if a unicode string is provided to __init__, it is encoded in
    utf-8 by default.

    When packed they are length-prefixed with a u32.
    """
    DEFAULT_ENCODING = 'utf-8'
    def __init__(self, value, encoding=DEFAULT_ENCODING):
        if isinstance(value, String):
            value = value.value
        if not isinstance(value, bytes):
            if encoding is None:
                raise ValueError('encoding is None, so value must be a bytes object')
            value = value.encode(encoding)
        super(String, self).__init__(value)

    def _packdata(self):
        return self.value

    @classmethod
    def _unpackdata(cls, data):
        return cls(data, encoding=None)


class MPInt(_LPrefixed):
    """A multple-precision int.
    Stores ints as a length-prefixed (u32) two's-complement integer.
    """
    def __init__(self, value):
        if isinstance(value, MPInt):
            value = value.value
        super(MPInt, self).__init__(int(value))

    def _packdata(self):
        if self.value == 0:
            return b''
        return compact_bit_pack(self.value, True)

    @classmethod
    def _unpackdata(cls, data):
        if not data:
            return cls(0)
        return cls(int.from_bytes(data, 'big', signed=True))


class NameList(_LPrefixed):
    """A NameList is an ordered sequence of ascii-encoded strings.

    Names 'MUST NOT' have commas, so no need for escaping.
    """
    def __init__(self, value):
        if isinstance(value, NameList):
            value = value.value
        super(NameList, self).__init__(tuple(value))

    def _packdata(self):
        return b','.join(x.encode('ascii') for x in self.value)

    @classmethod
    def _unpackdata(cls, data):
        if not data:
            return cls(())
        return cls(x.decode('ascii') for x in data.split(b','))


# A base composite type.
class Sequence(BaseType):
    """A sequence of specified types.

    Subclass this and override TYPES to be a tuple of types.
    This will pack and unpack as a list of num_repeats repetitions of
    each TYPE. For example::


        class NameValue(Sequence):
            TYPES = (String, Byte)

        values = [(String('a'), (1)), (String('b'), Byte(2))]
        packed = (UInt32(2).pack() +
                  String('a').pack() + Byte(1).pack() +
                  String('b').pack() + Byte(2).pack())
        assert NameValue(2, values).pack() == packed



    """
    TYPES = None
    def __init__(self, value):
        assert all(len(v) == len(self.TYPES) for v in value)
        assert all(isinstance(e, t) for v in value for e, t in zip(v, self.TYPES))
        super(Sequence, self).__init__(list(value))

    def pack(self):
        parts = [UInt32(len(self.value)).pack()]
        parts.extend(e.pack() for seq in self.value for e in seq)
        return b''.join(parts)

    @classmethod
    def unpack_from(cls, stream):
        num_repeats = UInt32.unpack_from(stream).value
        values = [tuple(t.unpack_from(stream) for t in cls.TYPES)
                  for _ in range(num_repeats)]
        return cls(values)

    def append(self, entry):
        """A helper: Add entry to the sequence. It should be a tuple matching
        TYPES
        """
        assert len(entry) == len(self.TYPES)
        assert all(isinstance(e, t) for e, t in zip(entry, self.TYPES))
        self.value.append(entry)



@enum.unique
class Direction(enum.Enum):
    outbound = 1
    inbound = 2

@enum.unique
class Location(enum.Enum):
    local = 1
    remote = 2