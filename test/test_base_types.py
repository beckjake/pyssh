"""Tests for the types in the base_types module.

Data type tests will use the examples in the openssh RFC, where applicable.
"""
from __future__ import print_function, division, absolute_import
from __future__ import unicode_literals
import unittest
from pyssh import base_types
import io

import pytest

def _assert_dstreams_equal(cls, data, expect):
    stream = io.BytesIO(data)
    assert cls.unpack_from(stream) == expect
    assert expect.pack() == data


class TestRawBytes(unittest.TestCase):
    def test_zero(self):
        data = b'\x00'*16
        expect = base_types.RawByte16(data)
        _assert_dstreams_equal(base_types.RawByte16, data, expect)

    def test_ff(self):
        data = b'\xFF'*16
        expect = base_types.RawByte16(data)
        _assert_dstreams_equal(base_types.RawByte16, data, expect)

    def test_insufficient(self):
        data = b'\x00'*8
        with pytest.raises(base_types.InsufficientDataError):
            base_types.RawByte16.unpack_from(io.BytesIO(data))


class TestBoolean(unittest.TestCase):
    def test_zero(self):
        data = b'\x00'
        expect = base_types.Boolean(0)
        _assert_dstreams_equal(base_types.Boolean, data, expect)

    def test_one(self):
        data = b'\x01'
        expect = base_types.Boolean(1)
        _assert_dstreams_equal(base_types.Boolean, data, expect)

    def test_ff(self):
        data = b'\xFF'
        expect = base_types.Boolean(255)
        assert base_types.Boolean.unpack_from(io.BytesIO(data)) == expect

    def test_pack_ff(self):
        with pytest.raises(AssertionError):
            data = base_types.Boolean(255).pack()

    def test_already_bool(self):
        first = base_types.Boolean(0)
        second = base_types.Boolean(first)
        assert second.value == first.value

    def test_fix(self):
        obj = base_types.Boolean(255)
        assert obj != base_types.Boolean(1)
        assert obj.fix() == base_types.Boolean(1)

class TestByte(unittest.TestCase):
    def test_zero(self):
        data = b'\x00'
        expect = base_types.Byte(0)
        _assert_dstreams_equal(base_types.Byte, data, expect)

    def test_one(self):
        data = b'\x01'
        expect = base_types.Byte(1)
        _assert_dstreams_equal(base_types.Byte, data, expect)

    def test_ff(self):
        data = b'\xFF'
        expect = base_types.Byte(255)
        _assert_dstreams_equal(base_types.Byte, data, expect)

    def test_already_byte(self):
        first = base_types.Byte(0)
        second = base_types.Byte(first)
        assert second.value == first.value

class TestUInt32(unittest.TestCase):
    def test_zero(self):
        data = b'\x00\x00\x00\x00'
        expect = base_types.UInt32(0)
        _assert_dstreams_equal(base_types.UInt32, data, expect)

    def test_ff(self):
        data = b'\x00\x00\x00\xFF'
        expect = base_types.UInt32(255)
        _assert_dstreams_equal(base_types.UInt32, data, expect)

    def test_big(self):
        data = b'\x29\xB7\xF4\xAA'
        expect = base_types.UInt32(699921578)
        _assert_dstreams_equal(base_types.UInt32, data, expect)

    def test_already_uint32(self):
        first = base_types.UInt32(0)
        second = base_types.UInt32(first)
        assert second.value == first.value

class TestUInt64(unittest.TestCase):
    def test_zero(self):
        data = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        expect = base_types.UInt64(0)
        _assert_dstreams_equal(base_types.UInt64, data, expect)

    def test_ff(self):
        data = b'\x00\x00\x00\x00\x00\x00\x00\xFF'
        expect = base_types.UInt64(255)
        _assert_dstreams_equal(base_types.UInt64, data, expect)

    def test_medium(self):
        data = b'\x00\x00\x00\x00\x29\xB7\xF4\xAA'
        expect = base_types.UInt64(699921578)
        _assert_dstreams_equal(base_types.UInt64, data, expect)

    def test_big(self):
        data = b'\xF5\x01\xD5\x6E\x88\x22\x07\x22'
        expect = base_types.UInt64(17654626684976105250)
        _assert_dstreams_equal(base_types.UInt64, data, expect)

    def test_already_uint64(self):
        first = base_types.UInt64(0)
        second = base_types.UInt64(first)
        assert second.value == first.value

class TestString(unittest.TestCase):
    def test_empty(self):
        data = b'\x00\x00\x00\x00'
        expect = base_types.String('')
        _assert_dstreams_equal(base_types.String, data, expect)

    def test_ascii(self):
        data = b'\x00\x00\x00\x05\x68\x65\x6C\x6C\x6F'
        expect = base_types.String('hello')
        _assert_dstreams_equal(base_types.String, data, expect)

    def test_utf8(self):
        data = b'\x00\x00\x00\x08\xE1\x88\x92\x68\x65\x6C\x6C\x6F'
        expect = base_types.String('\u1212'+'hello')
        _assert_dstreams_equal(base_types.String, data, expect)

    def test_already_string(self):
        first = base_types.String(b'')
        second = base_types.String(first)
        assert second.value == first.value

    def test_insufficient_data(self):
        stream = io.BytesIO(b'\xFF\x00\x00\x00\x00')
        with pytest.raises(base_types.InsufficientDataError):
            base_types.String.unpack_from(stream)

    def test_no_encoding_error(self):
        with pytest.raises(ValueError):
            base_types.String(u'hello', encoding=None)




class TestMPInt(unittest.TestCase):
    def test_zero(self):
        data = b'\x00\x00\x00\x00'
        expect = base_types.MPInt(0)
        _assert_dstreams_equal(base_types.MPInt, data, expect)

    def test_bigpos(self):
        data = b'\x00\x00\x00\x08\x09\xA3\x78\xF9\xB2\xE3\x32\xA7'
        expect = base_types.MPInt(0x9a378f9b2e332a7)
        _assert_dstreams_equal(base_types.MPInt, data, expect)

    def test_msb_zero(self):
        data = b'\x00\x00\x00\x02\x00\x80'
        expect = base_types.MPInt(0x80)
        _assert_dstreams_equal(base_types.MPInt, data, expect)

    def test_big_msb_zero(self):
        data = b'\x00\x00\x00\x08\x00\x80\x00\x80\x00\x80\x00\x80'
        expect = base_types.MPInt(0x80008000800080)
        _assert_dstreams_equal(base_types.MPInt, data, expect)

    def test_negative(self):
        data = b'\x00\x00\x00\x02\xED\xCC'
        expect = base_types.MPInt(-0x1234)
        _assert_dstreams_equal(base_types.MPInt, data, expect)

    def test_bigger_negative(self):
        data = b'\x00\x00\x00\x05\xFF\x21\x52\x41\x11'
        expect = base_types.MPInt(-0xDEADBEEF)
        _assert_dstreams_equal(base_types.MPInt, data, expect)

    def test_already_mpint(self):
        first = base_types.MPInt(0)
        second = base_types.MPInt(first)
        assert second.value == first.value

    def test_insufficient_data(self):
        stream = io.BytesIO(b'\xFF\x00\x00\x00\x00')
        with pytest.raises(base_types.InsufficientDataError):
            base_types.MPInt.unpack_from(stream)


class TestNameList(unittest.TestCase):
    def test_empty(self):
        data = b'\x00\x00\x00\x00'
        expect = base_types.NameList(())
        _assert_dstreams_equal(base_types.NameList, data, expect)

    def test_one(self):
        data = b'\x00\x00\x00\x04\x7A\x6C\x69\x62'
        expect = base_types.NameList([u'zlib'])
        _assert_dstreams_equal(base_types.NameList, data, expect)

    def test_two(self):
        data = b'\x00\x00\x00\x09\x7A\x6C\x69\x62\x2C\x6E\x6F\x6E\x65'
        expect = base_types.NameList([u'zlib', u'none'])
        _assert_dstreams_equal(base_types.NameList, data, expect)

    def test_already_namelist(self):
        first = base_types.NameList([])
        second = base_types.NameList(first)
        assert second.value == first.value

    def test_insufficient_data(self):
        stream = io.BytesIO(b'\xFF\x00\x00\x00\x00')
        with pytest.raises(base_types.InsufficientDataError):
            base_types.NameList.unpack_from(stream)


# some assorted standalone tests...
class TestMisc(unittest.TestCase):
    def test_classproperty_obj(self):
        class Foo(object):
            BAR = 'something'
            @base_types.classproperty
            def whatever(cls):
                return cls.BAR

        assert Foo.whatever == Foo.BAR
        assert Foo().whatever == Foo.BAR

    def test_str(self):
        class Foo(base_types.BaseType):
            def __init__(self, value):
                self.value = value

        assert str(Foo(1)) == 'Foo(1)'
        assert str(Foo('test')) == "Foo('test')"

    def test_eq(self):
        class Foo(base_types.BaseType):
            pass

        assert Foo(1) == Foo(1)
        assert Foo(1) != Foo(2)

    def test_invalid_eq(self):
        class Foo(base_types.BaseType):
            pass
        class Bar(base_types.BaseType):
            pass

        with pytest.raises(TypeError):
            Foo(1) == Bar(1)

